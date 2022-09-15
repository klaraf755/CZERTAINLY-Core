package com.czertainly.core.security.authz;

import com.czertainly.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authz.opa.OpaClient;
import com.czertainly.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.czertainly.core.security.authz.opa.dto.OpaRequestDetails;
import com.czertainly.core.security.authz.opa.dto.OpaRequestedResource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Aspect
public class ObjectFilterAspect {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private final OpaClient opaClient;

    private final OpaSecuredAnnotationMetadataExtractor opaSecuredAnnotationMetadataExtractor;

    public ObjectFilterAspect(@Autowired OpaClient opaClient, @Autowired OpaSecuredAnnotationMetadataExtractor opaSecuredAnnotationMetadataExtractor) {
        this.opaClient = opaClient;
        this.opaSecuredAnnotationMetadataExtractor = opaSecuredAnnotationMetadataExtractor;
    }

    @Around("@annotation(ExternalAuthorization)")
    public Object obtainObjectAccessData(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] arguments = joinPoint.getArgs();
        SecurityFilter secFilter = getSecurityFilter(arguments);

        if (secFilter == null) {
            logger.trace("No ObjectFilter was found, invoking joint point without filter.");
            return joinPoint.proceed();
        } else {
            logger.trace("ObjectFilter has been found. Going to obtain list of allowed objects.");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (!(auth instanceof CzertainlyAuthenticationToken))
                throw new RuntimeException("Unsupported authentication type.");

            Collection<ExternalAuthorizationConfigAttribute> attributes = createAttributesFromAnnotation(joinPoint);

            OpaObjectAccessResult result = obtainObjectAccess((CzertainlyAuthenticationToken) auth, attributes);

            logger.trace(String.format("User has the following object access rights. %s", result.toString()));

            secFilter.addAllowedObjects(result.getAllowedObjects());
            secFilter.addDeniedObjects(result.getForbiddenObjects());
            secFilter.setAreOnlySpecificObjectsAllowed(!result.isActionAllowedForGroupOfObjects());
            return joinPoint.proceed(arguments);
        }
    }

    private Collection<ExternalAuthorizationConfigAttribute> createAttributesFromAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        ExternalAuthorization externalAuthorization = method.getAnnotation(ExternalAuthorization.class);

        return opaSecuredAnnotationMetadataExtractor.extractAttributes(externalAuthorization);
    }

    private SecurityFilter getSecurityFilter(Object[] arguments) {
        SecurityFilter filter = null;

        for (Object argument : arguments) {
            if (argument instanceof SecurityFilter) {
                filter = (SecurityFilter) argument;
                break;
            }
        }
        return filter;
    }

    private OpaObjectAccessResult obtainObjectAccess(CzertainlyAuthenticationToken authentication, Collection<ExternalAuthorizationConfigAttribute> attributes) {

        Map<String, String> properties = attributes
                .stream()
                .collect(Collectors.toMap(ExternalAuthorizationConfigAttribute::getAttributeName, ExternalAuthorizationConfigAttribute::getAttributeValueAsString));

        OpaRequestedResource resource = new OpaRequestedResource(properties);

        return this.opaClient.checkObjectAccess(OpaPolicy.OBJECTS.policyName, resource, authentication.getPrincipal().getRawData(), new OpaRequestDetails(null));
    }

}