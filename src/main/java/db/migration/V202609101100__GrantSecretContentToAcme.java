package db.migration;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DatabaseAuthMigration;
import com.otilm.core.util.DatabaseMigration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/**
 * Grants {@code SECRET:GET_SECRET_CONTENT} to the {@code acme} role.
 * <p>
 * An ACME profile may require External Account Binding, naming the secrets whose content is the HMAC key a binding
 * must verify under. Verifying one therefore reads a secret, and it happens on a newAccount request, which the
 * platform already runs as the {@code acme} system user. Without this grant that read is denied and every account
 * registration against such a profile fails.
 * <p>
 * The grant is resource-level: the ACME identity can read any secret's content, not only those a profile names. It is
 * the same breadth the protocol already has over the resources it enrols against, and it keeps the read behind the
 * one authorization gate every other caller passes rather than behind a bypass.
 */
// Flyway mandates the V<version>__<Description> class-name format, which cannot match Sonar's S101 identifier pattern.
@SuppressWarnings("java:S101")
public class V202609101100__GrantSecretContentToAcme extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202609101100__GrantSecretContentToAcme.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        Map<Resource, List<ResourceAction>> addedResourceActions = new EnumMap<>(Resource.class);
        addedResourceActions.put(Resource.SECRET, List.of(ResourceAction.GET_SECRET_CONTENT));

        // On a fresh install this migration runs before Core's catalog sync, and the auth service rejects
        // permissions naming an unknown resource/action. Additive no-op where the pair is already known.
        DatabaseAuthMigration.seedResources(addedResourceActions);

        String roleUuid = DatabaseAuthMigration.getSystemRolesMapping().get(AuthHelper.ACME_USERNAME);
        if (roleUuid == null) {
            throw new IllegalStateException("System role '%s' not found".formatted(AuthHelper.ACME_USERNAME));
        }

        DatabaseAuthMigration.updateRolePermissions(roleUuid, addedResourceActions);
    }
}
