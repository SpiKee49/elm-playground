port module Port.Middleware exposing
    ( SecurityPolicy(..)
    , sanitize
    , sanitizeRegex
    , send
    , sendString
    , requestComparison
    , receiveComparison
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
import Regex


-- PORT — single generic outgoing port carrying policy tag + payload

port sendToJS : { policy : String, data : Value } -> Cmd msg


-- COMPARISON PORTS — used by the Comparison tab to run DOMPurify on the JS side
-- and return results back to Elm for side-by-side display.

{-| Send a list of payloads to JavaScript so DOMPurify can sanitize them.
Each record carries only the id (for later matching) and the raw input string. -}
port requestComparison : List { id : String, input : String } -> Cmd msg


{-| Receive DOMPurify results from JavaScript.
  textOnly — result of DOMPurify.sanitize(input, { ALLOWED_TAGS: [] })
  safeHtml — result of DOMPurify.sanitize(input) with default config -}
port receiveComparison : (List { id : String, textOnly : String, safeHtml : String } -> msg) -> Sub msg


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


-- REGEX-BASED SANITIZATION ENGINE (baseline for comparison)

{-| Regex-based sanitizer — kept alongside the tokenizer for side-by-side
comparison in the demo UI.  Not intended for production use: regex operates
on the raw byte stream and can be defeated by encoding tricks that the
tokenizer catches. -}
sanitizeRegex : SecurityPolicy -> String -> String
sanitizeRegex policy rawString =
    case policy of
        AllowTextOnly ->
            rawString
                |> removeNullBytes
                |> Regex.replace tagPattern (\_ -> "")
                |> String.replace "&" "&amp;"
                |> String.replace "<" "&lt;"
                |> String.replace ">" "&gt;"
                |> String.replace "\"" "&quot;"
                |> String.replace "'" "&#x27;"

        AllowSafeHtml ->
            rawString
                |> removeNullBytes
                |> Regex.replace scriptPattern (\_ -> "")
                |> Regex.replace dangerousTagPattern (\_ -> "")
                |> Regex.replace svgPattern (\_ -> "")
                |> Regex.replace eventHandlerPattern (\_ -> "")
                |> Regex.replace jsInAttrPattern (\_ -> "blocked:")

        AllowUrl ->
            if isSafeUrl rawString then rawString else ""

        Passthrough ->
            rawString


-- NORMALIZATION HELPERS

removeNullBytes : String -> String
removeNullBytes =
    String.replace "\u{0000}" ""


normalizeUrl : String -> String
normalizeUrl url =
    url
        |> String.trim
        |> String.replace "\u{0000}" ""
        |> String.replace "\t" ""
        |> String.replace "\n" ""
        |> String.replace "\r" ""


isSafeUrl : String -> Bool
isSafeUrl url =
    let
        normalized = normalizeUrl url
        lower      = String.toLower normalized
    in
    not (String.startsWith "javascript:" lower)
        && not (String.startsWith "data:" lower)
        && not (String.startsWith "vbscript:" lower)
        && not (Regex.contains htmlEntityStartPattern normalized)


-- REGEX PATTERNS

tagPattern : Regex.Regex
tagPattern =
    Regex.fromString "<[^>]*>"
        |> Maybe.withDefault Regex.never


scriptPattern : Regex.Regex
scriptPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = True }
        "<script[\\s\\S]*?</script>"
        |> Maybe.withDefault Regex.never


dangerousTagPattern : Regex.Regex
dangerousTagPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "<(iframe|object|embed|link|meta|base|form)(\\s[^>]*)?>?"
        |> Maybe.withDefault Regex.never


svgPattern : Regex.Regex
svgPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = True }
        "<svg[\\s\\S]*?</svg>"
        |> Maybe.withDefault Regex.never


eventHandlerPattern : Regex.Regex
eventHandlerPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "\\bon\\w+\\s*="
        |> Maybe.withDefault Regex.never


jsInAttrPattern : Regex.Regex
jsInAttrPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "(src|href|action)\\s*=\\s*[\"']?\\s*javascript:"
        |> Maybe.withDefault Regex.never


htmlEntityStartPattern : Regex.Regex
htmlEntityStartPattern =
    Regex.fromString "^&#"
        |> Maybe.withDefault Regex.never
