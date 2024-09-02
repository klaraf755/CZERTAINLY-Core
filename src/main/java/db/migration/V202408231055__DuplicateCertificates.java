package db.migration;


import com.czertainly.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;


public class V202408231055__DuplicateCertificates extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202408231055__DuplicateCertificates.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202408231055__DuplicateCertificates.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {

        mergeDuplicateCertificates(context);
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute("ALTER TABLE certificate ADD UNIQUE (fingerprint);");
        }


        deleteDuplicateCrls(context);
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute("ALTER TABLE crl ADD UNIQUE (issuer_dn, serial_number);");
        }


    }

    private void deleteDuplicateCrls(Context context) throws SQLException {
        List<String> uuidsToDelete = new ArrayList<>();
        ResultSet duplicateCrls;
        try (final Statement select = context.getConnection().createStatement()) {
            duplicateCrls = select.executeQuery("SELECT STRING_AGG(quote_literal(uuid::text),',') AS uuids FROM crl  GROUP BY issuer_dn, serial_number HAVING COUNT(*) > 1");

            while (duplicateCrls.next()) {
                List<String> duplicateUuids = new ArrayList<>(List.of(duplicateCrls.getString("uuids").split(",")));
                String crlToKeepUuid = duplicateUuids.getFirst();
                for (String uuid : duplicateUuids) {
                    ResultSet crl;
                    String query = "SELECT ca_certificate_uuid FROM crl WHERE uuid = ?;";
                    try (final PreparedStatement statement = context.getConnection().prepareStatement(query)) {
                        statement.setString(1, uuid);
                        crl = statement.executeQuery();
                    }
                    crl.next();
                    if (crl.getString("ca_certificate_uuid") != null) {
                        crlToKeepUuid = uuid;
                        break;
                    }
                }
                duplicateUuids.remove(crlToKeepUuid);
                uuidsToDelete.addAll(duplicateUuids);
            }
            if (!uuidsToDelete.isEmpty())
                select.execute("DELETE FROM crl WHERE uuid IN (" + String.join(",", uuidsToDelete) + ");");
        }
    }

    private void mergeDuplicateCertificates(Context context) throws SQLException {
        try (final Statement executeStatement = context.getConnection().createStatement()) {
            ResultSet duplicateCertificatesGrouped;
            try (final Statement select = context.getConnection().createStatement()) {
                duplicateCertificatesGrouped = select.executeQuery("SELECT STRING_AGG(quote_literal(uuid::text), ',' ORDER BY i_cre ASC) AS uuids FROM certificate GROUP BY fingerprint HAVING COUNT(uuid) > 1;");
            }
            while (duplicateCertificatesGrouped.next()) {

                String duplicateCertificatesUuids = duplicateCertificatesGrouped.getString("uuids");
                String certificateToKeepUuid = List.of(duplicateCertificatesUuids.split(",")).getFirst();
                String placeholders = String.join(", ", Collections.nCopies(List.of(duplicateCertificatesUuids.split(",")).size(), "?"));

                logger.debug("Processing duplicate certificates with UUIDs {0}. Keeping certificate with UUID {1}.", duplicateCertificatesUuids, certificateToKeepUuid);

                // Merge groups
                String updateGroupsQuery = "UPDATE group_association SET object_uuid = ? WHERE resource = 'CERTIFICATE' AND object_uuid IN (" + placeholders + ") AND group_uuid " +
                        "NOT IN (SELECT group_uuid FROM group_association WHERE object_uuid = ? );";
                
                executeStatement.addBatch("UPDATE group_association SET object_uuid = " + certificateToKeepUuid + " WHERE resource = 'CERTIFICATE' AND object_uuid IN (" + duplicateCertificatesUuids + ") AND group_uuid " +
                        "NOT IN (SELECT group_uuid FROM group_association WHERE object_uuid = " + certificateToKeepUuid + ");");
                executeStatement.addBatch("DELETE FROM group_association WHERE resource = 'CERTIFICATE' AND object_uuid in (" + duplicateCertificatesUuids + ") AND object_uuid != " + certificateToKeepUuid + ";");

                logger.debug("Groups of duplicate certificates have been merged.");


                // Find first certificate with owner and set that owner for certificate being kept
                executeStatement.addBatch("UPDATE owner_association SET object_uuid = " + certificateToKeepUuid + " WHERE uuid = (" +
                        "SELECT oa.uuid FROM owner_association oa JOIN certificate c ON c.uuid = oa.object_uuid  WHERE resource = 'CERTIFICATE' AND object_uuid in (" + duplicateCertificatesUuids +
                        ") ORDER BY c.i_cre ASC LIMIT 1) and resource = 'CERTIFICATE';");
                executeStatement.addBatch("DELETE FROM owner_association WHERE resource = 'CERTIFICATE' AND object_uuid in (" + duplicateCertificatesUuids + ") AND object_uuid != " + certificateToKeepUuid + ";");

                logger.debug("Owner has been set for merged certificate.");


                // Find first certificate with RA Profile and set that RA Profile for certificate being kept
                executeStatement.addBatch("UPDATE certificate SET ra_profile_uuid = ( SELECT ra_profile_uuid FROM certificate c WHERE uuid in (" + duplicateCertificatesUuids +
                        ") AND ra_profile_uuid IS NOT NULL ORDER BY c.i_cre ASC LIMIT 1) WHERE uuid = " + certificateToKeepUuid + ";");

                logger.debug("RA Profile has been set for merged certificate.");


                // Merge attributes

                executeStatement.addBatch("DELETE FROM attribute_content_2_object WHERE object_type = 'CERTIFICATE' AND object_uuid in (" + duplicateCertificatesUuids + ") AND object_uuid != " + certificateToKeepUuid + ";");

                logger.debug("Attributes of duplicate certificates have been deleted.");


                // Merge protocols
                executeStatement.addBatch("UPDATE certificate_protocol_association SET certificate_uuid = " + certificateToKeepUuid + " WHERE certificate_uuid IN (" + duplicateCertificatesUuids + ") " +
                        "AND protocol_profile_uuid NOT IN (SELECT protocol_profile_uuid FROM certificate_protocol_association " +
                        "WHERE certificate_uuid = " + certificateToKeepUuid + ");");
                executeStatement.addBatch("DELETE FROM certificate_protocol_association WHERE certificate_uuid in (" + duplicateCertificatesUuids + ") AND certificate_uuid != " + certificateToKeepUuid + ";");

                logger.debug("Protocol associations of duplicate certificates have been merged.");


                // Crl
                executeStatement.addBatch("DELETE FROM crl WHERE ca_certificate_uuid in (" + duplicateCertificatesUuids + ") AND ca_certificate_uuid != " + certificateToKeepUuid + ";");
                logger.debug("CRLs linked to duplicate certificates have been deleted.");


                // SCEP Profile
                executeStatement.addBatch("UPDATE scep_profile SET ca_certificate_uuid = " + certificateToKeepUuid + "WHERE ca_certificate_uuid in (" + duplicateCertificatesUuids + ");");
                logger.debug("SCEP Profiles have been linked to merged certificates.");


                // Certificate History

                executeStatement.addBatch("DELETE FROM certificate_event_history WHERE certificate_uuid in (" + duplicateCertificatesUuids + ") AND certificate_uuid != " + certificateToKeepUuid + ";");

                logger.debug("Certificate event history of duplicate certificates has been deleted.");


                // Delete Approvals

                executeStatement.addBatch("DELETE FROM approval WHERE object_uuid != " + certificateToKeepUuid + "AND resource = 'CERTIFICATE' AND object_uuid IN (" + duplicateCertificatesUuids + ");");

                logger.debug("Approvals of duplicate certificates have been deleted.");

                // Set user UUID

                executeStatement.addBatch("UPDATE certificate SET user_uuid = ( SELECT user_uuid FROM certificate c WHERE uuid in (" + duplicateCertificatesUuids +
                        ") AND user_uuid IS NOT NULL ORDER BY c.i_cre ASC LIMIT 1) WHERE uuid = " + certificateToKeepUuid + ";");
                logger.debug("User has been set for merged certificate.");


                // Delete duplicates
                executeStatement.addBatch("DELETE FROM certificate WHERE uuid != " + certificateToKeepUuid + "AND uuid IN (" + duplicateCertificatesUuids + ");");
                logger.debug("Duplicate certificates have been deleted.");


                // Keep only one certificate content
                executeStatement.addBatch("DELETE FROM certificate_content WHERE id IN ( SELECT certificate_content_id FROM certificate " +
                        "WHERE uuid IN (" + duplicateCertificatesUuids + ") AND uuid != " + certificateToKeepUuid + ");");

                logger.debug("Deleted certificate content of duplicate certificates.");

            }
            executeStatement.executeBatch();
        }
    }


}
