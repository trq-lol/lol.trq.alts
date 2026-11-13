package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.account.SkinProblem;
import org.junit.jupiter.api.Test;

/**
 * Pins the migration from the retired error enums and exceptions to {@link Kind}. The retired types are
 * gone, so their constants are named here as strings: each maps to exactly one kind ({@code none} for
 * success, {@code kept} for an outcome constant that is still there). The CHANGELOG's "Error kinds"
 * table must say the same thing, row for row, so the document a host migrates by cannot drift from
 * what the code was tested to do.
 */
class ErrorKindMigrationTableTest {

    private static final String NONE = "none";
    private static final String KEPT = "kept";

    /** Former constant or case, as the CHANGELOG writes it, to the kind it becomes. */
    static final Map<String, String> TABLE = table();

    private static Map<String, String> table() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("FailureReason.NONE", NONE);
        rows.put("FailureReason.UNKNOWN", "UNKNOWN");
        rows.put("FailureReason.REAUTH_REQUIRED", "REAUTH_REQUIRED");
        rows.put("FailureReason.INVALID_TOKEN", "UNAUTHORIZED");
        rows.put("FailureReason.NETWORK", "NETWORK");
        rows.put("FailureReason.NOT_CONFIGURED", "NOT_CONFIGURED");
        rows.put("FailureReason.NOT_ENTITLED", "NOT_ENTITLED");
        rows.put("FailureReason.RATE_LIMITED", "RATE_LIMITED");
        rows.put("FailureReason.XBOX_DENIED", "XBOX_DENIED");
        rows.put("FailureReason.DECLINED", "DECLINED");
        rows.put("FailureReason.TIMED_OUT", "TIMED_OUT");
        rows.put("AccountException.tokenRefused()", "UNAUTHORIZED");
        rows.put("AccountException.notFound()", "NOT_FOUND");
        rows.put("AccountException.notFound() from ProfileService.fetch", "NOT_ENTITLED");
        rows.put("AccountException.rateLimited()", "RATE_LIMITED");
        rows.put("AccountException status 5xx or 408", "NETWORK");
        rows.put("AccountException status 400 or 422", "INVALID_INPUT");
        rows.put("AccountException status 409", "CONFLICT");
        rows.put("AccountException another status", "UNKNOWN");
        rows.put("AccountException status 0, unreachable", "NETWORK");
        rows.put("AccountException status 0, unreadable answer", "PROTOCOL");
        rows.put("XstsAuthException", "XBOX_DENIED");
        rows.put("RefreshRejectedException.permanent()", "REAUTH_REQUIRED");
        rows.put("RefreshRejectedException.rateLimited()", "RATE_LIMITED");
        rows.put("RefreshRejectedException, an outage", "NETWORK");
        rows.put("RefreshRejectedException, another refusal", "UNAUTHORIZED");
        rows.put("RefreshRejectedException, invalid_client or unauthorized_client", "NOT_CONFIGURED");
        for (SkinProblem problem : SkinProblem.values()) {
            rows.put("SkinValidationException.Reason." + problem.name(), "INVALID_INPUT");
        }
        rows.put("NameChangeResult.Outcome.CHANGED", KEPT);
        rows.put("NameChangeResult.Outcome.INVALID_NAME", KEPT);
        rows.put("NameChangeResult.Outcome.UNAVAILABLE", KEPT);
        rows.put("NameChangeResult.Outcome.NOT_ENTITLED", "NOT_ENTITLED");
        rows.put("NameChangeResult.Outcome.UNAUTHORIZED", "UNAUTHORIZED");
        rows.put("NameChangeResult.Outcome.RATE_LIMITED", "RATE_LIMITED");
        rows.put("NameChangeResult.Outcome.FAILED", KEPT);
        rows.put("ProfileCreationResult.Outcome.CREATED", KEPT);
        rows.put("ProfileCreationResult.Outcome.INVALID_NAME", KEPT);
        rows.put("ProfileCreationResult.Outcome.DUPLICATE", KEPT);
        rows.put("ProfileCreationResult.Outcome.NOT_ALLOWED", KEPT);
        rows.put("ProfileCreationResult.Outcome.NOT_ENTITLED", "NOT_ENTITLED");
        rows.put("ProfileCreationResult.Outcome.UNAUTHORIZED", "UNAUTHORIZED");
        rows.put("ProfileCreationResult.Outcome.RATE_LIMITED", "RATE_LIMITED");
        rows.put("ProfileCreationResult.Outcome.FAILED", KEPT);
        rows.put("ClaimResult.StopReason.CLAIMED", KEPT);
        rows.put("ClaimResult.StopReason.WINDOW_ELAPSED", KEPT);
        rows.put("ClaimResult.StopReason.RATE_LIMITED", "RATE_LIMITED");
        rows.put("ClaimResult.StopReason.TERMINAL_FAILURE", KEPT);
        rows.put("ClaimResult.StopReason.CANCELLED", KEPT);
        rows.put("ClaimResult.StopReason.UNKNOWN", "UNKNOWN");
        rows.put("Store loadError(), saveError(), loadWarning() strings", "STORAGE");
        rows.put("build()'s IllegalStateException, store file in use", "CONFLICT");
        rows.put("build()'s IllegalStateException, store not lockable", "STORAGE");
        rows.put("CookieFile.read's IOException", "INVALID_INPUT");
        return rows;
    }

    /** Every constant the retired enums had, so none is left out of the table. */
    private static final List<String> FORMER_FAILURE_REASONS = List.of(
            "NONE",
            "UNKNOWN",
            "REAUTH_REQUIRED",
            "INVALID_TOKEN",
            "NETWORK",
            "NOT_CONFIGURED",
            "NOT_ENTITLED",
            "RATE_LIMITED",
            "XBOX_DENIED",
            "DECLINED",
            "TIMED_OUT");

    private static final List<String> FORMER_NAME_OUTCOMES =
            List.of("CHANGED", "INVALID_NAME", "UNAVAILABLE", "NOT_ENTITLED", "UNAUTHORIZED", "RATE_LIMITED", "FAILED");

    private static final List<String> FORMER_CREATION_OUTCOMES = List.of(
            "CREATED",
            "INVALID_NAME",
            "DUPLICATE",
            "NOT_ALLOWED",
            "NOT_ENTITLED",
            "UNAUTHORIZED",
            "RATE_LIMITED",
            "FAILED");

    private static final List<String> FORMER_STOP_REASONS =
            List.of("CLAIMED", "WINDOW_ELAPSED", "RATE_LIMITED", "TERMINAL_FAILURE", "CANCELLED", "UNKNOWN");

    @Test
    void everyFormerConstantHasExactlyOneRow() {
        for (String reason : FORMER_FAILURE_REASONS) {
            assertTrue(TABLE.containsKey("FailureReason." + reason), reason);
        }
        for (String outcome : FORMER_NAME_OUTCOMES) {
            assertTrue(TABLE.containsKey("NameChangeResult.Outcome." + outcome), outcome);
        }
        for (String outcome : FORMER_CREATION_OUTCOMES) {
            assertTrue(TABLE.containsKey("ProfileCreationResult.Outcome." + outcome), outcome);
        }
        for (String reason : FORMER_STOP_REASONS) {
            assertTrue(TABLE.containsKey("ClaimResult.StopReason." + reason), reason);
        }
        assertEquals(
                Set.of("UNREADABLE", "EMPTY", "TOO_LARGE", "NOT_PNG", "WRONG_DIMENSIONS"),
                Arrays.stream(SkinProblem.values()).map(Enum::name).collect(Collectors.toSet()),
                "SkinProblem replaces SkinValidationException.Reason constant for constant");
    }

    @Test
    void everyRowNamesOneKindThatExists() {
        Set<String> kinds = Arrays.stream(Kind.values()).map(Enum::name).collect(Collectors.toSet());
        for (Map.Entry<String, String> row : TABLE.entrySet()) {
            String kind = row.getValue();
            assertTrue(
                    kind.equals(NONE) || kind.equals(KEPT) || kinds.contains(kind),
                    row.getKey() + " maps to " + kind + ", which is not a kind");
        }
    }

    /** The outcome constants still there are exactly the ones the table says are kept. */
    @Test
    void theKeptRowsAreTheConstantsThatRemain() {
        assertKept("NameChangeResult.Outcome.", lol.trq.alts.account.NameChangeResult.Outcome.values());
        assertKept("ProfileCreationResult.Outcome.", lol.trq.alts.account.ProfileCreationResult.Outcome.values());
        assertKept("ClaimResult.StopReason.", lol.trq.alts.account.ClaimResult.StopReason.values());
    }

    private static void assertKept(String prefix, Enum<?>[] remaining) {
        Set<String> kept = TABLE.entrySet().stream()
                .filter(row -> row.getKey().startsWith(prefix) && row.getValue().equals(KEPT))
                .map(row -> row.getKey().substring(prefix.length()))
                .collect(Collectors.toSet());
        assertEquals(Arrays.stream(remaining).map(Enum::name).collect(Collectors.toSet()), kept, prefix);
    }

    @Test
    void theChangelogTableMirrorsThisOneRowForRow() throws Exception {
        List<String> lines = Files.readAllLines(Path.of("CHANGELOG.md"), StandardCharsets.UTF_8);
        int unreleased = lines.indexOf("## [Unreleased]");
        assertTrue(unreleased >= 0, "the CHANGELOG has an [Unreleased] section");
        int heading = lines.subList(unreleased, lines.size()).indexOf("### Error kinds");
        assertTrue(heading >= 0, "the [Unreleased] section has the error-kind table");

        List<List<String>> rows = new ArrayList<>();
        boolean inTable = false;
        for (String line : lines.subList(unreleased + heading + 1, lines.size())) {
            if (line.startsWith("|")) {
                inTable = true;
                List<String> cells = Arrays.stream(
                                line.substring(1, line.lastIndexOf('|')).split("\\|", -1))
                        .map(cell -> cell.strip().replace("`", ""))
                        .toList();
                if (!cells.get(0).equals("Former") && !cells.get(0).startsWith("---")) {
                    rows.add(cells);
                }
            } else if (inTable) {
                break;
            }
        }

        List<String> documented =
                rows.stream().map(cells -> cells.get(0) + " -> " + cells.get(1)).toList();
        List<String> pinned = TABLE.entrySet().stream()
                .map(row -> row.getKey() + " -> " + row.getValue())
                .toList();
        assertEquals(pinned, documented, "the CHANGELOG table and this test disagree");
        for (List<String> cells : rows) {
            assertFalse(cells.get(1).isBlank(), cells.get(0));
        }
    }
}
