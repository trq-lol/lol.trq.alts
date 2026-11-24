# Sign-in

Every route returns a `CompletableFuture<LoginResult>` from `alts.loginService()`. `LoginMode.ADD` also stores the
account.

| Route | Use it for |
|---|---|
| `loginMicrosoft` | The system browser |
| `loginDeviceCode` | A host with no browser or no free port |
| `loginAccount` | An account you already hold, renewed if needed |
| `loginRefreshToken` | A refresh token |
| `loginCookie`, `loginCookieFile` | Exported browser cookies |
| `loginSession` | A session token |
| `loginOffline` | Offline play |

## Azure and legacy applications

`MicrosoftAuthConfig.of(id)` is for an Azure application. Use `legacyMsa(id)` for a credential from a legacy MSA
application: the OAuth form is refused there with `400`. Legacy applications work with refresh tokens but not with the
browser route.

Override the scope or endpoints with `withScope`, `withEndpoints` or `withDeviceCodeEndpoints` only if you front the
services yourself.

## Device code

Show the user a code to enter on Microsoft's page, from any device.

```java
// Called once, off the render thread. Show the address exactly as given: the user has to be
// able to see that they are typing the code into the identity provider's page and nowhere else.
DeviceCodePrompt prompt = (userCode, verificationUri, expiresAt) ->
        render("Open " + verificationUri + " and enter " + userCode + " before " + expiresAt);

// Start this only on the user's own action. A device code signs in whoever started the flow,
// so a code shown to someone else is a phishing lure.
alts.loginService().loginDeviceCode(prompt, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
        return;
    }
    AltsFailure failure = result.failure().orElseThrow();
    switch (failure.kind()) {
        // The user said no. Nothing to retry until they ask again.
        case DECLINED -> render("Sign-in cancelled");
        // The code ran out before it was entered; starting again issues a fresh one.
        case TIMED_OUT -> showRetry("The code expired");
        // The service asked to be left alone. Wait before starting another.
        case RATE_LIMITED -> showRetry("Too many attempts; try again shortly");
        // Signed in, but Xbox Live will not authorize the account; xstsError() says why.
        case XBOX_DENIED ->
            showError("Xbox Live refused this account: "
                    + failure.xstsError().orElseThrow());
        default -> showError(result.message());
    }
});
```

- **Only start this when the user asks.** A code shown to someone else is a phishing lure.
- The prompt runs once, off your main thread, and must return promptly.
- Cancelling the future stops the polling. Polling also stops when the code expires.
- Tested against a scripted server, not the live service.

## Stored accounts

A Minecraft token lasts about a day. `loginAccount` renews it from the stored refresh token, without a browser:

```java
// Reuses the stored session if it is still live; otherwise renews from the refresh token,
// persists the rotated credential, and installs the session — all without a browser.
alts.loginService().loginAccount(account).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
    }
});
```

It renews when the token has expired, and once more if a live-looking token is refused. It never loops.

## Refresh tokens

```java
alts.loginService().loginRefreshToken(refreshToken, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        // Always the rotated value; persist it for any account the store does not hold.
        persist(result.account().refreshToken());
    } else if (result.failure().orElseThrow().kind() == AltsFailure.Kind.NOT_CONFIGURED) {
        // Only the routes that talk to Microsoft can report this one.
        showError("Microsoft login is not configured");
    }
});
```

The service usually replaces the refresh token each time it is used, and the old one stops working.

- **Accounts in the store** are updated for you.
- **Any other account** is not, including one from a vault or one signed in with `LoginMode.DIRECT`. Save
  `result.account().refreshToken()` after every sign-in, or the next renewal fails.

A server error or a dropped connection never discards a refresh token. A permanent rejection does.

## Cookie files

```java
alts.loginService().loginCookieFile(chosen, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
    } else {
        showError(result.message());
    }
});
```

- Reads Netscape and JSON exports, and text that lost its structure in a copy and paste.
- Uses only `live.com` cookies and sends them only over HTTPS.
- A missing, empty or oversized file is a failed result of kind `UNAUTHORIZED`. Messages never contain the path.
- `CookieFile.read(Path)` gives you the text on its own, and throws kind `INVALID_INPUT` for a file it cannot use.
- The services can change this route without notice. It was tested against a scripted server only.

The library opens no windows. Use its extension list in your file picker:

```java
CookieFile.EXTENSIONS   // ["txt", "json", "cookies"], no leading dot
```
