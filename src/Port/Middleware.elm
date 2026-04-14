port module Port.Middleware exposing
    ( SecurityPolicy(..)
    , sanitize
    , send
    , sendString
    , requestComparison
    , receiveComparison
    )

{-|
Port.Middleware — XSS protection library for Elm → JavaScript port communication.

## Design rationale

Browsers apply their own normalization pipeline *before* interpreting HTML
and URLs. A naive regex sanitizer checks the raw string and misses payloads
that look safe in Elm but decode into executable content in the browser.
The defense used here is: **normalize first, then pattern-match**.

### Normalization steps applied

1. **Null byte removal** (`U+0000`): Some parsers treat `\0` as a string
   terminator, causing them to see only a prefix of the full string.

2. **Control character stripping from URLs** (`\t`, `\n`, `\r`): The WHATWG
   URL specification explicitly strips U+0009, U+000A, U+000D from URL strings
   before parsing. `java\tscript:` is therefore identical to `javascript:`
   from the browser's perspective. We must remove these before checking the
   scheme. See: https://url.spec.whatwg.org/#url-parsing

3. **HTML entity start rejection for URLs**: A URL beginning with `&#NNN;`
   will be decoded by the HTML parser before the URL parser sees it.
   `&#106;avascript:alert(1)` in `href="…"` becomes `javascript:alert(1)`.
   Legitimate URLs never start with numeric entities, so rejection is safe.

### Regex limitations (acknowledged POC scope)

This library uses regex as a baseline sanitizer, which is inherently
incomplete against a full HTML parser-based attack surface. The approach is
intentionally scoped as a proof-of-concept demonstrating the port-middleware
pattern and compile-time policy enforcement in Elm. A production deployment
should combine this with a server-side HTML parser (e.g., DOMPurify on the
JS side, or a server-rendered sanitizer).
-}

import Json.Encode as Encode exposing (Value)
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

{-| Send a pre-sanitized string value through the port. The string is
sanitized in Elm before crossing the boundary. -}
sendString : SecurityPolicy -> String -> Cmd msg
sendString policy rawString =
    let
        safeString = sanitize policy rawString
    in
    sendToJS { policy = policyToString policy, data = Encode.string safeString }


{-| Send an arbitrary JSON Value through the port without string sanitization.
Use this for non-string payloads (numbers, booleans, encoded records) or when
the value is internally generated and inherently trusted (Passthrough). -}
send : SecurityPolicy -> Value -> Cmd msg
send policy payload =
    sendToJS { policy = policyToString policy, data = payload }


-- SANITIZATION ENGINE

{-| Apply the sanitization rule for the given policy to a raw string.
Exposed so that test suites can call it directly without going through ports.
-}
sanitize : SecurityPolicy -> String -> String
sanitize policy rawString =
    case policy of
        AllowTextOnly ->
            -- Strip ALL HTML markup, then HTML-escape the remaining text.
            -- Normalization removes null bytes for clean output; all other
            -- obfuscation is irrelevant because we destroy every < … > block.
            rawString
                |> removeNullBytes
                |> Regex.replace tagPattern (\_ -> "")
                |> String.replace "&" "&amp;"
                |> String.replace "<" "&lt;"
                |> String.replace ">" "&gt;"
                |> String.replace "\"" "&quot;"
                |> String.replace "'" "&#x27;"

        AllowSafeHtml ->
            -- Normalize null bytes, then strip dangerous constructs in order:
            --   1. <script>…</script> blocks
            --   2. Dangerous container/void tags that load resources or run code
            --      (iframe, object, embed, svg, link, meta, base, form)
            --   3. Inline event-handler attributes (on*)
            --   4. javascript: in href/src/action attributes
            -- Order matters: remove whole blocks before scanning attributes.
            rawString
                |> removeNullBytes
                |> Regex.replace scriptPattern (\_ -> "")
                |> Regex.replace dangerousTagPattern (\_ -> "")
                |> Regex.replace svgPattern (\_ -> "")
                |> Regex.replace eventHandlerPattern (\_ -> "")
                |> Regex.replace jsInAttrPattern (\_ -> "blocked:")

        AllowUrl ->
            -- Normalize (strip chars browsers ignore), then block dangerous schemes.
            if isSafeUrl rawString then rawString else ""

        Passthrough ->
            -- No sanitization. Use only for internally generated, trusted values.
            rawString


-- NORMALIZATION HELPERS

{-| Remove null bytes. Some parsers treat U+0000 as a string terminator,
which can cause mismatches between what the sanitizer sees and what the
browser processes. -}
removeNullBytes : String -> String
removeNullBytes =
    String.replace "\u{0000}" ""


{-| Normalize a URL string to match the form the browser's URL parser will see.
The WHATWG URL spec strips U+0009 (tab), U+000A (LF), U+000D (CR) and U+0000
(null) from URL strings during parsing. We apply the same stripping so that
our scheme check reflects what the browser will actually execute. -}
normalizeUrl : String -> String
normalizeUrl url =
    url
        |> String.trim
        |> String.replace "\u{0000}" ""
        |> String.replace "\t" ""
        |> String.replace "\n" ""
        |> String.replace "\r" ""


-- URL SAFETY

{-| Return True if the URL is safe to use in an href/src context.

Blocked:
  - javascript: scheme (arbitrary code execution)
  - data:        scheme (can encode full HTML documents)
  - vbscript:    scheme (legacy IE code execution)
  - Any URL whose normalized form begins with an HTML entity (&#…)
    because the HTML parser decodes entities before the URL parser runs,
    allowing &#106;avascript: → javascript: bypass.
-}
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

{-| Matches any HTML/XML tag, including tags containing newlines.
[^>] matches any character except > — including \n — so <scr\nipt> is caught. -}
tagPattern : Regex.Regex
tagPattern =
    Regex.fromString "<[^>]*>"
        |> Maybe.withDefault Regex.never


{-| Matches <script>…</script> blocks, case-insensitive and spanning newlines.
[\s\S]*? is the cross-line wildcard (Elm's Regex has no DOTALL flag). -}
scriptPattern : Regex.Regex
scriptPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = True }
        "<script[\\s\\S]*?</script>"
        |> Maybe.withDefault Regex.never


{-| Matches opening tags of elements that must never appear in user-supplied HTML:
  - iframe, object, embed  — load external resources / run plugins
  - link, meta, base        — load stylesheets, force redirects, hijack base URL
  - form                    — can phish via action= attribute

We strip the opening tag (which carries the dangerous attributes). The
corresponding closing tag (</iframe> etc.) is harmless on its own.

[^>]* inside a character class DOES match newlines in JS regex, so multiline
attribute lists are caught without needing the multiline flag. -}
dangerousTagPattern : Regex.Regex
dangerousTagPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "<(iframe|object|embed|link|meta|base|form)(\\s[^>]*)?>?"
        |> Maybe.withDefault Regex.never


{-| Matches entire <svg>…</svg> blocks. SVG is special because it has its own
execution context: it can contain <script> tags and event handlers on any
element. We strip the whole block rather than just the opening tag. -}
svgPattern : Regex.Regex
svgPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = True }
        "<svg[\\s\\S]*?</svg>"
        |> Maybe.withDefault Regex.never


{-| Matches inline event-handler attributes: onclick=, onmouseover=, onload=, …

\b    — word boundary (prevents matching e.g. "font=")
on\w+ — the "on" prefix followed by the event name
\s*=  — optional whitespace before = (catches "onclick = alert(1)")

Case-insensitive flag handles onCLICK=, ONCLICK=, etc. -}
eventHandlerPattern : Regex.Regex
eventHandlerPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "\\bon\\w+\\s*="
        |> Maybe.withDefault Regex.never


{-| Matches javascript: scheme inside href, src, or action attributes.
Covers quoted, unquoted, and whitespace-padded values:
  href="javascript:…"
  href='javascript:…'
  href=javascript:…
  href = "javascript:…"  (whitespace around =) -}
jsInAttrPattern : Regex.Regex
jsInAttrPattern =
    Regex.fromStringWith { caseInsensitive = True, multiline = False }
        "(src|href|action)\\s*=\\s*[\"']?\\s*javascript:"
        |> Maybe.withDefault Regex.never


{-| Matches a string that begins with an HTML numeric entity reference (&#…).
Used in isSafeUrl to reject entity-encoded scheme bypasses.
Legitimate URLs (https://, /, ./, ../path) never start with &#. -}
htmlEntityStartPattern : Regex.Regex
htmlEntityStartPattern =
    Regex.fromString "^&#"
        |> Maybe.withDefault Regex.never
