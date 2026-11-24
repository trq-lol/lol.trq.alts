# Shared vault

Share accounts between people through hosts that see only ciphertext. The vault implements
[AVP](https://github.com/trqlmao/avp) 0.5, a draft protocol.

The owner signs every change to members, policy and hosts. Members sign every write. Your client verifies all of it and
trusts no host. **Read the [threat model](../SECURITY.md) before relying on it.**

The calls in these samples block, so run them off your main thread.

## Create a repository

```java
// A first contact: nobody vouched for this host's key yet, and from here on the snapshot and every
// token carry it and each later connection pins it. So the user compares it out of band, with the
// key the host's operator published, before anything is created or stored.
VaultHost home = alts.vault().connectFirstContact(homeHost).join();
if (!confirmedOutOfBand("Vault host key: " + home.hostKey())) {
    return null; // not the host the user meant, or not checked: nothing was created or stored
}

HostSecrets secrets = alts.secrets();
OwnerIdentity owner = OwnerIdentity.generate();
showOnce(owner.phrase()); // the owner writes it down: it is the only way back to the owner key
byte[] entropy = owner.entropy();
try {
    secrets.put(OWNER_ENTROPY, Base64.getEncoder().encodeToString(entropy));
} finally {
    Arrays.fill(entropy, (byte) 0);
}
SharedVault vault = SharedVault.create(home, owner).join();
secrets.put(SNAPSHOT, vault.snapshot().toJson());
return vault.locator().text();
```

- **The 24-word phrase is the owner.** Anyone with it controls the repository. Show it once, and store only the entropy,
  encrypted.
- **Confirm the host key on first contact.** `connectFirstContact` accepts any key, so compare it with the one the
  operator published before creating anything. Every other `connect` refuses a different key with `PROTOCOL`.
- **The snapshot is a secret.** Save it encrypted, for example in `alts.secrets()`, after every operation.
- Link a second owner device with `LinkSession`, comparing the 6-digit code on both.
- A host is reached at `https://<locator>` unless `vaultHostAddress` maps it elsewhere.

## Invite and join

The joiner reads the locator and makes an invite token:

```java
RepoLocator locator = RepoLocator.parse(pastedLocator);
VaultHost home = alts.vault().connect(locator).join(); // matched by the locator's host key
InviteToken token = SharedVault.prepareJoin(home, member, locator).join();
return token.text();
```

The owner compares fingerprints, then invites:

```java
InviteToken token = InviteToken.parse(pastedInvite);
if (!token.fingerprint().equals(fingerprintTheMemberSees)) {
    return; // not the person the owner meant to invite
}
SharedVault vault = resumeOwner(alts);
vault.invite(token).join();
alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
```

The joiner joins:

```java
RepoLocator locator = RepoLocator.parse(pastedLocator);
VaultHost home = alts.vault().connect(locator).join();
SharedVault vault = SharedVault.join(home, member, locator).join();
alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
return vault.accounts();
```

Compare the fingerprint outside the app. The data key is wrapped only to keys in the token, never to keys a host serves.
Whitespace in a pasted token is ignored; anything else wrong is `INVALID_INPUT`.

## Write and sync

Resume from the snapshot:

```java
HostSecrets secrets = alts.secrets();
byte[] entropy = Base64.getDecoder().decode(secrets.find(OWNER_ENTROPY).orElseThrow());
OwnerIdentity owner;
try {
    owner = OwnerIdentity.fromEntropy(entropy);
} finally {
    Arrays.fill(entropy, (byte) 0);
}
VaultSnapshot snapshot = VaultSnapshot.fromJson(secrets.find(SNAPSHOT).orElseThrow());
VaultHost home = alts.vault().connect(snapshot).join(); // the home host, by the key it had
return SharedVault.resume(home, owner, snapshot).join();
```

Then write and sync:

```java
SharedVault vault = resumeOwner(alts);
try {
    vault.put(account).join();
    vault.update(
                    renewed.uuid(),
                    held -> held.withTokens(renewed.accessToken(), renewed.refreshToken(), renewed.expiresAt()))
            .join();
    SyncReport report = vault.sync().join();
    if (report.policyTurnedOn()) {
        showOnce("This repository now shares refresh tokens.");
    }
    report.divergedAt().ifPresent(seq -> showOnce("Two owner devices diverged at state " + seq));
    List<VaultMember> leaving = vault.processLeaves().join();
    leaving.forEach(m -> showOnce("Removed " + m.fingerprint() + ", who left"));
} catch (CompletionException e) {
    AltsFailure failure = ((AltsException) e.getCause()).failure();
    if (failure.kind() == AltsFailure.Kind.PROTOCOL) {
        showOnce("The vault host served something that does not verify: " + failure.message());
    }
} finally {
    alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
}
```

- **Use `update(uuid, edit)` to change an account.** It writes only the changed fields. `put(account)` with a stale
  object can undo someone else's edit; `put(base, edited)` writes just the difference.
- **Act on the `SyncReport`.** It reports a diverged owner chain, sharing turned on, heads that could not be read and
  members who want to leave.
- **The owner manages members** with `roster()`, `removeMember()` and `processLeaves()`. Members can `leave()` but not
  invite. Removing someone rotates the key.
- **A forged state or a rollback fails with `PROTOCOL`** and nothing is adopted. A forged commit is dropped and counted
  in `discardedCommits()`.
- Nothing is copied into the local account store.

## Share refresh tokens

They are not shared by default.

```java
// Withholding is the default for a new repository.
render(vault.sharesRefreshTokens() ? "sharing" : "withholding");

// Owner only. What has been shared stays shared: turning it off later stops future sharing only.
vault.setShareRefreshTokens(true).join();
```

**Sharing cannot be undone.** A refresh token someone received stays theirs, even after you turn sharing off or remove
them. To revoke it, revoke the account's sessions and change its password.

## Import a 0.4 repository

```java
try {
    return LegacyVaultReader.read(manifestJson, envelopeJson, identity);
} catch (AltsException e) {
    switch (e.kind()) {
        // The text the host saved is not strict JSON: fetch or export it again.
        case INVALID_INPUT -> showError("That is not a saved 0.4 repository");
        // Not this member's repository, a manifest and envelope that do not belong together, or
        // not a 0.4 document at all.
        case PROTOCOL -> showError("This identity cannot read that repository");
        // The key did not unwrap or the payload did not authenticate: wrong identity, or tampered.
        case CRYPTO -> showError("The repository could not be decrypted");
        default -> showError(e.getMessage());
    }
    return List.of();
}
```

This only reads. Nothing in a 0.4 repository is signed, so review the accounts before you add them to a new one. Fetch
the JSON yourself, authenticating with `VaultIdentity.signChallenge`, or export it with 0.12.
