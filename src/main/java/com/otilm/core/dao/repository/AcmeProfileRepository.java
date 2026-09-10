package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeProfileRepository extends SecurityFilterRepository<AcmeProfile, Long> {
    Optional<AcmeProfile> findByUuid(UUID uuid);

    boolean existsByName(String name);

    @EntityGraph(attributePaths = {"raProfile"})
    Optional<AcmeProfile> findByName(String name);

    List<AcmeProfile> findByRaProfile(RaProfile raProfile);

    /**
     * Names of the profiles that accept the given secret as an External Account Binding key. Native because the column
     * is a PostgreSQL array and JPQL has no containment operator for one.
     */
    @Query(value = "SELECT p.name FROM acme_profile p WHERE :secretUuid = ANY(p.eab_secret_uuids)", nativeQuery = true)
    List<String> findNamesByEabSecretUuid(@Param("secretUuid") UUID secretUuid);
}
