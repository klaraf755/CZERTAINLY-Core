package com.czertainly.core.service.impl;

import com.czertainly.api.clients.EntityInstanceApiClient;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.client.entity.EntityInstanceUpdateRequestDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.entity.EntityInstanceDto;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.EntityInstanceReference;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.AttributeService;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.EntityInstanceService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.SecretMaskingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class EntityInstanceServiceImpl implements EntityInstanceService {

    private static final Logger logger = LoggerFactory.getLogger(EntityInstanceServiceImpl.class);
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private ConnectorService connectorService;
    private CredentialService credentialService;
    private EntityInstanceApiClient entityInstanceApiClient;
    private AttributeService attributeService;

    @Autowired
    public void setEntityInstanceReferenceRepository(EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setEntityInstanceApiClient(EntityInstanceApiClient entityInstanceApiClient) {
        this.entityInstanceApiClient = entityInstanceApiClient;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.LIST)
    public List<EntityInstanceDto> listEntityInstances(SecurityFilter filter) {
        return entityInstanceReferenceRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(EntityInstanceReference::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DETAIL)
    public EntityInstanceDto getEntityInstance(SecuredUUID entityUuid) throws ConnectorException {
        EntityInstanceReference entityInstanceReference = entityInstanceReferenceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));

        if (entityInstanceReference.getConnector() == null) {
            throw new NotFoundException("Connector associated with the Entity is not found. Unable to load details");
        }

        com.czertainly.api.model.connector.entity.EntityInstanceDto entityProviderInstanceDto = entityInstanceApiClient.getEntityInstance(entityInstanceReference.getConnector().mapToDto(),
                entityInstanceReference.getEntityInstanceUuid());

        EntityInstanceDto entityInstanceDto = new EntityInstanceDto();
        entityInstanceDto.setAttributes(SecretMaskingUtil.maskSecret(AttributeDefinitionUtils.getResponseAttributes(entityProviderInstanceDto.getAttributes())));
        entityInstanceDto.setName(entityProviderInstanceDto.getName());
        entityInstanceDto.setUuid(entityInstanceReference.getUuid().toString());
        entityInstanceDto.setConnectorUuid(entityInstanceReference.getConnector().getUuid().toString());
        entityInstanceDto.setKind(entityInstanceReference.getKind());
        entityInstanceDto.setConnectorName(entityInstanceReference.getConnectorName());
        entityInstanceDto.setCustomAttributes(attributeService.getCustomAttributesWithValues(entityUuid.getValue(), Resource.ENTITY));
        return entityInstanceDto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.CREATE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.CREATE)
    public EntityInstanceDto createEntityInstance(com.czertainly.api.model.client.entity.EntityInstanceRequestDto request) throws AlreadyExistException, ConnectorException {
        if (entityInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(EntityInstanceReference.class, request.getName());
        }

        if(request.getConnectorUuid() == null){
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }

        Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromString(request.getConnectorUuid()));

        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;
        attributeService.validateCustomAttributes(request.getCustomAttributes(), Resource.ENTITY);
        List<DataAttribute> attributes = connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connector.getUuid()), codeToSearch,
                request.getAttributes(), request.getKind());

        // Load complete credential data
        credentialService.loadFullCredentialData(attributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(attributes));
        entityInstanceDto.setKind(request.getKind());
        entityInstanceDto.setName(request.getName());

        com.czertainly.api.model.connector.entity.EntityInstanceDto response = entityInstanceApiClient.createEntityInstance(connector.mapToDto(), entityInstanceDto);

        EntityInstanceReference entityInstanceRef = new EntityInstanceReference();
        entityInstanceRef.setEntityInstanceUuid((response.getUuid()));
        entityInstanceRef.setName(request.getName());
        //entityInstanceRef.setStatus("connected"); // TODO: status of the Entity
        entityInstanceRef.setConnector(connector);
        entityInstanceRef.setKind(request.getKind());
        entityInstanceRef.setConnectorName(connector.getName());
        entityInstanceReferenceRepository.save(entityInstanceRef);

        attributeService.createAttributeContent(entityInstanceRef.getUuid(), request.getCustomAttributes(), Resource.ENTITY);
        logger.info("Entity {} created with Kind {}", entityInstanceRef.getUuid(), entityInstanceRef.getKind());

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeService.getCustomAttributesWithValues(entityInstanceRef.getUuid(), Resource.ENTITY));
        return dto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.CHANGE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.UPDATE)
    public EntityInstanceDto editEntityInstance(SecuredUUID entityUuid, EntityInstanceUpdateRequestDto request) throws ConnectorException {
        EntityInstanceReference entityInstanceRef = entityInstanceReferenceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));

        EntityInstanceDto ref = getEntityInstance(entityUuid);
        Connector connector = connectorService.getConnectorEntity(SecuredUUID.fromString(ref.getConnectorUuid()));

        FunctionGroupCode codeToSearch = FunctionGroupCode.ENTITY_PROVIDER;

        attributeService.validateCustomAttributes(request.getCustomAttributes(), Resource.ENTITY);
        List<DataAttribute> attributes = connectorService.mergeAndValidateAttributes(connector.getSecuredUuid(), codeToSearch,
                request.getAttributes(), ref.getKind());

        // Load complete credential data
        credentialService.loadFullCredentialData(attributes);

        EntityInstanceRequestDto entityInstanceDto = new EntityInstanceRequestDto();
        entityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(attributes));
        entityInstanceDto.setKind(entityInstanceRef.getKind());
        entityInstanceDto.setName(entityInstanceRef.getName());
        entityInstanceApiClient.updateEntityInstance(connector.mapToDto(),
                entityInstanceRef.getEntityInstanceUuid(), entityInstanceDto);
        entityInstanceReferenceRepository.save(entityInstanceRef);

        attributeService.updateAttributeContent(entityInstanceRef.getUuid(), request.getCustomAttributes(), Resource.ENTITY);
        logger.info("Entity {} updated with Kind {}", entityInstanceRef.getUuid(), entityInstanceRef.getKind());

        EntityInstanceDto dto = entityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeService.getCustomAttributesWithValues(entityInstanceRef.getUuid(), Resource.ENTITY));
        return dto;
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.CA_INSTANCE, operation = OperationType.DELETE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.DELETE)
    public void deleteEntityInstance(SecuredUUID entityUuid) throws ConnectorException {
        EntityInstanceReference entityInstanceRef = entityInstanceReferenceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));

        List<ValidationError> errors = new ArrayList<>();
        if (!entityInstanceRef.getLocations().isEmpty()) {
            errors.add(ValidationError.create("Entity instance {} has {} dependent Locations", entityInstanceRef.getName(),
                    entityInstanceRef.getLocations().size()));
            entityInstanceRef.getLocations().forEach(c -> errors.add(ValidationError.create(c.getName())));
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Could not delete Entity instance", errors);
        }

        entityInstanceApiClient.removeEntityInstance(entityInstanceRef.getConnector().mapToDto(), entityInstanceRef.getEntityInstanceUuid());
        attributeService.deleteAttributeContent(entityInstanceRef.getUuid(), Resource.ENTITY);
        entityInstanceReferenceRepository.delete(entityInstanceRef);

        logger.info("Entity instance {} was deleted", entityInstanceRef.getName());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.ATTRIBUTES, operation = OperationType.REQUEST)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public List<BaseAttribute> listLocationAttributes(SecuredUUID entityUuid) throws ConnectorException {
        EntityInstanceReference entityInstance = entityInstanceReferenceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));

        Connector connector = entityInstance.getConnector();

        return entityInstanceApiClient.listLocationAttributes(connector.mapToDto(), entityInstance.getEntityInstanceUuid());
    }

    @Override
    //@AuditLogged(originator = ObjectType.FE, affected = ObjectType.ATTRIBUTES, operation = OperationType.VALIDATE)
    @ExternalAuthorization(resource = Resource.ENTITY, action = ResourceAction.ANY)
    public void validateLocationAttributes(SecuredUUID entityUuid, List<RequestAttributeDto> attributes) throws ConnectorException {
        EntityInstanceReference entityInstance = entityInstanceReferenceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstanceReference.class, entityUuid));

        Connector connector = entityInstance.getConnector();

        entityInstanceApiClient.validateLocationAttributes(connector.mapToDto(), entityInstance.getEntityInstanceUuid(),
                attributes);
    }
}
