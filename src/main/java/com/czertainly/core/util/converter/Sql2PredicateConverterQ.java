package com.czertainly.core.util.converter;


import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.QCryptographicKey;
import com.czertainly.core.dao.entity.QCryptographicKeyItem;
import com.czertainly.core.dao.entity.QTokenProfile;
import com.czertainly.core.enums.SearchFieldNameEnumQ;
import com.czertainly.core.model.SearchFieldObject;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.*;
import com.querydsl.core.types.dsl.*;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.BiFunction;

public class Sql2PredicateConverterQ {

    public static Predicate mapSearchFilter2Predicates(final List<SearchFilterRequestDto> dtos, final EntityPathBase root) {
        BooleanBuilder predicate = new BooleanBuilder();
        PathBuilder<Object> cryptographicKeyItem = new PathBuilder<>(root.getType(), root.getMetadata());

//        QCryptographicKeyItem cryptographicKeyItem = QCryptographicKeyItem.cryptographicKeyItem;
        QCryptographicKey cryptographicKey = QCryptographicKey.cryptographicKey;
        QTokenProfile tokenProfile = QTokenProfile.tokenProfile;

        BooleanExpression predicateManual = root.in(JPAExpressions.selectFrom(QCryptographicKeyItem.cryptographicKeyItem)
                .join(QCryptographicKeyItem.cryptographicKeyItem.cryptographicKey, cryptographicKey)
                .join(cryptographicKey.tokenProfile, tokenProfile)
                .where(tokenProfile.name.eq("Token Profile")));
        List<SearchFilterRequestDto> attributeFilters = new ArrayList<>();
        for (final SearchFilterRequestDto dto : dtos) {
            if (dto.getFieldSource() == FilterFieldSource.PROPERTY) {
                predicate.and(processPropertyPredicate(dto, root));
            } else {
                attributeFilters.add(dto);
            }

        }

        return predicate;
    }

    private static BooleanExpression processPropertyPredicate(SearchFilterRequestDto dto, EntityPathBase root) {
        Object value = dto.getValue();
        FilterConditionOperator conditionOperator = dto.getCondition();
        SearchFieldNameEnumQ searchFieldNameEnumQ = SearchFieldNameEnumQ.findEnum(dto.getFieldIdentifier());
        Expression path = searchFieldNameEnumQ.getPathToProperty();

        // If the property is not immediate property of root object, but it is a property of another object/objects related to root object, then we need to join those tables
        if (searchFieldNameEnumQ.getJoins() != null) {
            return getPredicateForPluralProperty(root, searchFieldNameEnumQ.getJoins(), value, conditionOperator, (SimpleExpression) path);
        } else {
            return getPredicateForSingleProperty((SimpleExpression) path, value, conditionOperator);
        }
    }

    private static BooleanExpression getPredicateForPluralProperty(EntityPathBase root, List<List<Path>> joinExpressionsList, Object value, FilterConditionOperator operator, SimpleExpression pathToValue) {
//      SELECT * from certificate left join groups where (certificate.uuid in (select c.uuid from certificate c join group_association join groups on ... where group.name ) )
//       QCertificate.cert.raProfile.name = null
//        PathBuilder<Object> pathRoot = new PathBuilder<>(root.getType(), root.getMetadata());
//
        JPQLQuery joinExpression = JPAExpressions.selectFrom(root);
        for (List<Path> joinExpressions : joinExpressionsList) {
            if (joinExpressions.get(0) instanceof CollectionExpression<?, ?>) {
                joinExpression = joinExpression.join((CollectionExpression) joinExpressions.get(0), joinExpressions.get(1));
            } else {
             joinExpression = joinExpression.join((EntityPath) joinExpressions.get(0), joinExpressions.get(1));
            }
        }

        switch (operator) {
            case EQUALS -> {
                return QCryptographicKeyItem.cryptographicKeyItem.in((Collection<? extends CryptographicKeyItem>) joinExpression.where(getPredicateForSingleProperty(pathToValue, value, operator)));
            }
            case NOT_EQUALS -> {
                return root.notIn(joinExpression.where(getPredicateForSingleProperty(pathToValue, value, operator)));
            }
            case EMPTY -> {
                return root.notIn(joinExpression);
            }
            case NOT_EMPTY -> {
                return root.in(joinExpression);
            }
            default -> throw new ValidationException("Operator not supported for this property.");
        }
    }

    private static BooleanExpression getPredicateForSingleProperty(SimpleExpression pathToProperty, Object value, FilterConditionOperator conditionOperator) {
        if (value instanceof ArrayList<?> listOfValues) {
            BooleanExpression predicate = retrievePredicateForClassOrEnumProperty(listOfValues.get(0), pathToProperty, conditionOperator);

            for (int i = 1; i < listOfValues.size(); i++) {
                if (conditionOperator == FilterConditionOperator.EQUALS) {
                    predicate = predicate.or(retrievePredicateForClassOrEnumProperty(listOfValues.get(i), pathToProperty, conditionOperator));
                } else {
                    predicate = predicate.and(retrievePredicateForClassOrEnumProperty(listOfValues.get(i), pathToProperty, conditionOperator));
                }
            }
            return predicate;
        } else {
            return retrievePredicateForClassOrEnumProperty(value, pathToProperty, conditionOperator);
        }
    }

    private static BooleanExpression retrievePredicateForClassOrEnumProperty(Object value, SimpleExpression pathToProperty, FilterConditionOperator operator) {
        if (pathToProperty instanceof EnumPath) value = findEnumByCustomValue(value, pathToProperty.getType());
        return applyOperator(value, pathToProperty, operator);
    }

    private static BooleanExpression applyOperator(Object value, SimpleExpression pathToProperty, FilterConditionOperator operator) {
        if (pathToProperty instanceof StringPath) {
            return stringPropertyToPredicateMap.get(operator).apply(pathToProperty, value);
        } else if (pathToProperty instanceof NumberPath) {
            return numberPropertyToPredicateMap.get(operator).apply(pathToProperty, value);
        } else if (pathToProperty instanceof DateTimeExpression<?>) {
            return dateTimePropertyToPredicateMap.get(operator).apply(pathToProperty, value);

//            return dateTimePropertyToPredicateMap.get(operator).apply(pathToProperty, value);
        } else {
            return singularPropertyToPredicateMap.get(operator).apply(pathToProperty, value);
        }
    }

    private static Object findEnumByCustomValue(Object valueObject, Class<? extends IPlatformEnum> enumClass) {
        Optional<? extends IPlatformEnum> enumItem = Arrays.stream(enumClass.getEnumConstants()).filter(enumValue -> enumValue.getCode().equals(valueObject.toString())).findFirst();
        return enumItem.isPresent() ? enumItem.get() : null;
    }

    private static final Map<Class<? extends SimpleExpression>, Map<FilterConditionOperator, BiFunction<SimpleExpression, Object, BooleanExpression>>> pathTypeToPredicate;
    private static final Map<FilterConditionOperator, BiFunction<SimpleExpression, Object, BooleanExpression>> singularPropertyToPredicateMap;
    private static final Map<FilterConditionOperator, BiFunction<SimpleExpression, Object, BooleanExpression>> stringPropertyToPredicateMap;

    private static final Map<FilterConditionOperator, BiFunction<SimpleExpression, Object, BooleanExpression>> numberPropertyToPredicateMap;
    private static final Map<FilterConditionOperator, BiFunction<SimpleExpression, Object, BooleanExpression>> dateTimePropertyToPredicateMap;


    static {
        pathTypeToPredicate = new HashMap<>();

        singularPropertyToPredicateMap = new HashMap<>();

        singularPropertyToPredicateMap.put(FilterConditionOperator.EQUALS, (comparableExpression, value) -> comparableExpression.eq(value));
        singularPropertyToPredicateMap.put(FilterConditionOperator.NOT_EQUALS, (comparableExpression, value) -> comparableExpression.ne(value).or(comparableExpression.isNull()));
        singularPropertyToPredicateMap.put(FilterConditionOperator.EMPTY, (comparableExpression, value) -> (comparableExpression.isNull()));
        singularPropertyToPredicateMap.put(FilterConditionOperator.NOT_EMPTY, (comparableExpression, value) -> (comparableExpression.isNotNull()));

        stringPropertyToPredicateMap = new HashMap<>();
        stringPropertyToPredicateMap.put(FilterConditionOperator.STARTS_WITH, (comparableExpression, value) -> ((StringPath) comparableExpression).like(value + "%"));
        stringPropertyToPredicateMap.put(FilterConditionOperator.ENDS_WITH, (comparableExpression, value) -> ((StringPath) comparableExpression).like("%" + value));
        stringPropertyToPredicateMap.put(FilterConditionOperator.CONTAINS, (comparableExpression, value) -> ((StringPath) comparableExpression).contains((String) value));
        stringPropertyToPredicateMap.put(FilterConditionOperator.NOT_CONTAINS, (comparableExpression, value) -> ((StringPath) comparableExpression).notLike("%" + value + "%").or(comparableExpression.isNull()));
        stringPropertyToPredicateMap.putAll(singularPropertyToPredicateMap);


        pathTypeToPredicate.put(StringPath.class, stringPropertyToPredicateMap);

        numberPropertyToPredicateMap = new HashMap<>();
        numberPropertyToPredicateMap.putAll(singularPropertyToPredicateMap);
        numberPropertyToPredicateMap.put(FilterConditionOperator.GREATER, (expression, value) -> ((NumberPath) expression).gt((Number) value));
        numberPropertyToPredicateMap.put(FilterConditionOperator.LESSER, (expression, value) -> ((NumberPath) expression).lt((Number) value));

        dateTimePropertyToPredicateMap = new HashMap<>();

        dateTimePropertyToPredicateMap.putAll(singularPropertyToPredicateMap);


    }


}


