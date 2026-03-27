port module Port.Middleware exposing
    ( SecurityPolicy(..)
    , sanitize
    , send
    , sendString
    )

{-|
Port.Middleware — XSS protection library for Elm → JavaScript port communication.

## Design

Each outgoing port message carries a `SecurityPolicy` tag so the JavaScript
receiver can apply the correct DOM-insertion method.  The string payload is
sanitized in Elm *before* it crosses the port boundary.

### Sanitization engine

Sanitization is delegated to `Port.HtmlParser`, which uses a recursive-descent
tokenizer rather than regex.  See that module for a full explanation of why
a tokenizer is more robust than regex against obfuscated HTML payloads.

### Policies

| Policy        | What Elm does                                    | How JS should insert      |
|---------------|--------------------------------------------------|---------------------------|
| AllowTextOnly | Strip all tags; HTML-encode remaining text       | `textContent`             |
| AllowSafeHtml | Tokenize; keep allowlisted elements + attrs      | `innerHTML` (+ DOMPurify) |
| AllowUrl      | Block dangerous schemes and obfuscation variants | `.href` after check       |
| Passthrough   | No sanitization — trusted internal values only   | `console.log` / safe API  |
-}

import Json.Encode as Encode exposing (Value)
import Port.HtmlParser as HtmlParser


-- PORT — single generic outgoing port carrying policy tag + payload

port sendToJS : { policy : String, data : Value } -> Cmd msg


-- POLICIES

type SecurityPolicy
    = AllowTextOnly
    | AllowSafeHtml
    | AllowUrl
    | Passthrough


policyToString : SecurityPolicy -> String
policyToString policy =
    case policy of
        AllowTextOnly -> "text-only"
        AllowSafeHtml -> "safe-html"
        AllowUrl      -> "url"
        Passthrough   -> "passthrough"


-- PUBLIC API

{-| Send a string value through the port after sanitizing it with the given
policy.  The sanitized form is what actually crosses the Elm/JS boundary. -}
sendString : SecurityPolicy -> String -> Cmd msg
sendString policy rawString =
    let
        safeString = sanitize policy rawString
    in
    sendToJS { policy = policyToString policy, data = Encode.string safeString }


{-| Send an arbitrary JSON Value without string sanitization.  Use for
non-string payloads or internally generated trusted values (Passthrough). -}
send : SecurityPolicy -> Value -> Cmd msg
send policy payload =
    sendToJS { policy = policyToString policy, data = payload }


-- SANITIZATION ENGINE

{-| Apply the sanitization rule for the given policy.
Exposed so that the test suite can call it directly without going through
ports. -}
sanitize : SecurityPolicy -> String -> String
sanitize policy rawString =
    case policy of
        AllowTextOnly ->
            -- Tokenize the input, extract only text nodes (dropping all markup
            -- and the entire subtrees of dangerous elements), then HTML-encode
            -- the resulting plain text.
            HtmlParser.stripToText rawString

        AllowSafeHtml ->
            -- Tokenize and reconstruct using an allowlist of safe elements and
            -- attributes.  Dangerous element subtrees are dropped entirely.
            -- URL-bearing attributes (href, src) are validated by isSafeUrl
            -- before being emitted.
            HtmlParser.sanitize rawString

        AllowUrl ->
            -- Normalize (strip chars browsers ignore per WHATWG URL spec) then
            -- check the scheme.  Returns "" when blocked so the JS receiver
            -- can detect and display a "blocked" notice.
            if HtmlParser.isSafeUrl rawString then rawString else ""

        Passthrough ->
            -- No sanitization.  Use only for internally generated, fully
            -- trusted values — never for user input.
            rawString
