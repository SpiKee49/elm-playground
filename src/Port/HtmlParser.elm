module Port.HtmlParser exposing
    ( sanitize
    , stripToText
    , isSafeUrl
    )

{-|
Port.HtmlParser — tokenizer-based HTML sanitizer.

## Why a tokenizer instead of regex?

Regex operates on the raw byte stream and can be defeated by any encoding
trick that causes the *browser's* parser to see different content than the
regex did.  A tokenizer operates the same way the browser does:

    1. Split the input into a stream of typed tokens (text, open-tag,
       close-tag, comment, doctype).
    2. Inspect each token against an allowlist of safe elements and
       attributes.
    3. Reconstruct output only from tokens that pass the allowlist.

Obfuscation techniques that defeat regex — split tag names across newlines,
null bytes inside tag names, double-bracket tricks, attribute whitespace
before `=` — are all handled correctly here because the tokenizer sees the
same token boundaries the browser would.

## Allowlist

Elements: a safe subset of phrasing and flow content.  Everything that can
load external resources, execute scripts, or alter document structure is
absent (script, style, svg, iframe, object, embed, form, input, …).

Attributes: a global safe set plus `href`/`src` which are validated through
`isSafeUrl` before they are emitted.

## Layering

This tokenizer is Elm's first-pass defence.  The JavaScript side should add
DOMPurify as a second, independent parser-based pass before setting
`innerHTML`.  Neither pass alone is sufficient for all attack surface; both
together reduce it to near-zero for known techniques.
-}

import Set exposing (Set)


-- ── ALLOWLISTS ────────────────────────────────────────────────────────────────

{-| Elements permitted in sanitized HTML output. -}
safeElements : Set String
safeElements =
    Set.fromList
        [ "a", "abbr", "b", "bdi", "bdo", "blockquote", "br"
        , "caption", "cite", "code", "col", "colgroup"
        , "dd", "del", "dfn", "div", "dl", "dt"
        , "em", "figcaption", "figure"
        , "h1", "h2", "h3", "h4", "h5", "h6", "hr"
        , "i", "img", "ins", "kbd", "li", "mark"
        , "ol", "p", "pre", "q"
        , "rp", "rt", "ruby"
        , "s", "samp", "small", "span", "strong", "sub", "sup"
        , "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr"
        , "u", "ul", "var", "wbr"
        ]


{-| Attributes permitted on any allowlisted element.
Event-handler attributes (on*) are intentionally absent. -}
safeGlobalAttrs : Set String
safeGlobalAttrs =
    Set.fromList
        [ "class", "id", "lang", "dir", "title"
        , "role"
        , "aria-label", "aria-describedby", "aria-hidden", "aria-live"
        , "alt"
        , "width", "height"
        , "colspan", "rowspan", "scope"
        , "datetime", "cite"
        , "reversed", "start"
        ]


{-| Attributes whose values are URLs.  Validated through isSafeUrl; dropped
if the URL does not pass. -}
urlAttrs : Set String
urlAttrs =
    Set.fromList [ "href", "src" ]


{-| Elements whose *entire subtree* is dropped, not just their opening tag.
Each of these can execute scripts or load untrusted resources. -}
rawTextElements : Set String
rawTextElements =
    Set.fromList
        [ "script", "style", "noscript", "template"
        , "iframe", "object", "embed", "applet"
        , "svg", "math"
        ]


-- ── PUBLIC API ────────────────────────────────────────────────────────────────

{-| Sanitize an HTML string using tokenizer-based allowlist filtering.

Safe elements and attributes are preserved; everything else is stripped.
Elements that can execute code have their entire subtree dropped. -}
sanitize : String -> String
sanitize input =
    input
        |> removeNullBytes
        |> tokenize
        |> filterTokens
        |> renderTokens


{-| Strip all HTML tags and return safe, HTML-encoded plain text.

Text content inside dangerous elements (script, style, svg …) is also
dropped.  The result is safe to assign to `textContent` or to use inside
an HTML attribute value. -}
stripToText : String -> String
stripToText input =
    input
        |> removeNullBytes
        |> tokenize
        |> filterTokens
        |> List.filterMap extractText
        |> String.concat
        |> htmlEncode


{-| Return True when a URL is safe for use in `href` or `src` attributes.

Blocked schemes: javascript:, data:, vbscript:

Obfuscation vectors also blocked:

  - Tab / LF / CR injection — the WHATWG URL spec strips U+0009, U+000A,
    U+000D before parsing, so `java\tscript:` parses identically to
    `javascript:`.  We apply the same stripping before scheme comparison.
  - Null byte injection — same rationale.
  - HTML numeric-entity start (&#…) — the HTML parser decodes entities
    *before* the URL parser runs, so `&#106;avascript:` → `javascript:`.
    Legitimate URLs never start with `&#`. -}
isSafeUrl : String -> Bool
isSafeUrl url =
    let
        normalized = normalizeUrl url
        lower      = String.toLower normalized
    in
    not (String.startsWith "javascript:" lower)
        && not (String.startsWith "data:"       lower)
        && not (String.startsWith "vbscript:"   lower)
        && not (String.startsWith "&#"          normalized)


-- ── URL / NULL-BYTE NORMALIZATION ─────────────────────────────────────────────

normalizeUrl : String -> String
normalizeUrl url =
    url
        |> String.trim
        |> String.replace "\u{0000}" ""
        |> String.replace "\t"       ""
        |> String.replace "\n"       ""
        |> String.replace "\r"       ""


removeNullBytes : String -> String
removeNullBytes =
    String.replace "\u{0000}" ""


-- ── TOKEN TYPES ───────────────────────────────────────────────────────────────

type Token
    = TText String
    | TOpen  String (List Attr)  -- (element-name, attributes)
    | TClose String              -- element-name
    | TRaw                       -- comment / doctype / PI — always dropped


type alias Attr =
    { name  : String
    , value : String
    }


-- ── TOKENIZER ─────────────────────────────────────────────────────────────────
--
-- Recursive-descent, single-pass.  We consume the input string from left to
-- right; each helper function returns (token-or-value, remaining-string).
--
-- States handled:
--   Data         — plain text between tags
--   Comment      — <!-- … -->
--   Bogus decl   — <! not followed by --  (DOCTYPE etc.)
--   Close tag    — </name … >
--   Open tag     — <name attr* (/)?>
--     Attr       — name, name=value (double/single-quoted or unquoted)

tokenize : String -> List Token
tokenize src =
    tokenizeLoop src []


tokenizeLoop : String -> List Token -> List Token
tokenizeLoop remaining acc =
    case String.uncons remaining of
        Nothing ->
            List.reverse acc

        Just ( '<', rest ) ->
            let
                ( tok, after ) = parseTagToken rest
            in
            tokenizeLoop after (tok :: acc)

        _ ->
            -- Consume plain text up to the next '<'
            let
                ( text, after ) = spanBefore '<' remaining
            in
            tokenizeLoop after (TText text :: acc)


{-| Parse one token starting *after* the opening `<`.
Returns (token, string-after-closing->). -}
parseTagToken : String -> ( Token, String )
parseTagToken rest =
    case String.uncons rest of
        Nothing ->
            -- Lone `<` at end of input — emit as literal text
            ( TText "<", "" )

        Just ( '!', afterBang ) ->
            if String.startsWith "--" afterBang then
                -- HTML comment: <!-- … -->
                ( TRaw, findAfterCommentEnd (String.dropLeft 2 afterBang) )
            else
                -- DOCTYPE, bogus comment: skip everything to `>`
                ( TRaw, dropUntilAfter '>' afterBang )

        Just ( '/', afterSlash ) ->
            -- Close tag: </tagname … >
            let
                ( rawName, afterName ) = consumeTagName afterSlash
                name                  = String.toLower rawName
                after                 = dropUntilAfter '>' afterName
            in
            if String.isEmpty name then
                ( TRaw, after )
            else
                ( TClose name, after )

        Just ( ch, _ ) ->
            if isNameStartChar ch then
                -- Open (or self-closing) tag
                let
                    ( rawName, afterName ) = consumeTagName rest
                    name                  = String.toLower rawName
                    ( attrs, after )       = parseAttrs afterName
                in
                ( TOpen name attrs, after )
            else
                -- `<` followed by a non-name character — emit `<` as text
                ( TText "<", rest )


{-| Return the string after the first `-->` occurrence (end of comment). Returns "" when the comment is unterminated. -}
findAfterCommentEnd : String -> String
findAfterCommentEnd str =
    case String.indexes "-->" str of
        [] ->
            ""

        ( i :: _ ) ->
            String.dropLeft (i + 3) str


{-| Consume a tag name (letters, digits, `-`, `_`, `:`, `.`). -}
consumeTagName : String -> ( String, String )
consumeTagName =
    consumeWhile isNameChar


-- ── ATTRIBUTE PARSER ──────────────────────────────────────────────────────────

{-| Parse all attributes, stopping at `>` or end of input.
Returns (attribute-list, string-after->). -}
parseAttrs : String -> ( List Attr, String )
parseAttrs str =
    parseAttrsLoop (skipWs str) []


parseAttrsLoop : String -> List Attr -> ( List Attr, String )
parseAttrsLoop str acc =
    case String.uncons str of
        Nothing ->
            ( List.reverse acc, "" )

        Just ( '>', rest ) ->
            ( List.reverse acc, rest )

        Just ( '/', rest ) ->
            -- Self-closing `/>` — consume the `>` and stop
            case String.uncons rest of
                Just ( '>', afterGt ) ->
                    ( List.reverse acc, afterGt )

                _ ->
                    -- Lone `/` inside tag (malformed) — skip and continue
                    parseAttrsLoop rest acc

        _ ->
            let
                ( attr, afterAttr ) = parseOneAttr str
            in
            -- Guard against zero-progress (malformed input with no valid attr
            -- chars) to prevent an infinite loop.
            if String.isEmpty attr.name && afterAttr == str then
                ( List.reverse acc, dropUntilAfter '>' str )
            else
                parseAttrsLoop (skipWs afterAttr) (attr :: acc)


{-| Parse one attribute: name, and optionally `=` followed by a value. -}
parseOneAttr : String -> ( Attr, String )
parseOneAttr str =
    let
        ( rawName, afterName ) = consumeWhile isAttrNameChar str
        name                   = String.toLower rawName
        trimmed                = skipWs afterName
    in
    case String.uncons trimmed of
        Just ( '=', afterEq ) ->
            let
                ( value, after ) = parseAttrValue (skipWs afterEq)
            in
            ( { name = name, value = value }, after )

        _ ->
            -- Boolean attribute (no `=value`)
            ( { name = name, value = "" }, trimmed )


{-| Parse an attribute value: `"…"`, `'…'`, or unquoted token. -}
parseAttrValue : String -> ( String, String )
parseAttrValue str =
    case String.uncons str of
        Just ( '"', rest ) ->
            let
                ( value, after ) = spanBefore '"' rest
            in
            ( value, String.dropLeft 1 after )

        Just ( '\'', rest ) ->
            let
                ( value, after ) = spanBefore '\'' rest
            in
            ( value, String.dropLeft 1 after )

        _ ->
            -- Unquoted value: ends at whitespace, `>`, `"`, `'`, `` ` ``, `=`
            consumeWhile isUnquotedValueChar str


-- ── TOKEN FILTER ──────────────────────────────────────────────────────────────

{-| Walk the token list and apply the allowlist.

  - TText  → always kept
  - TRaw   → always dropped (comments, doctype)
  - TClose → kept if element is in safeElements
  - TOpen  for rawTextElements → enter skip-mode (drop subtree)
  - TOpen  for safeElements    → kept with filtered attributes
  - TOpen  for anything else   → tag dropped, text children kept
-}
filterTokens : List Token -> List Token
filterTokens tokens =
    filterHelp tokens 0 "" []


filterHelp : List Token -> Int -> String -> List Token -> List Token
filterHelp tokens skipDepth skipTag acc =
    case tokens of
        [] ->
            List.reverse acc

        tok :: rest ->
            if skipDepth > 0 then
                -- Inside a raw-text element: drop everything
                case tok of
                    TOpen name _ ->
                        -- Track nested same-element depth (e.g. nested <svg>)
                        if name == skipTag then
                            filterHelp rest (skipDepth + 1) skipTag acc
                        else
                            filterHelp rest skipDepth skipTag acc

                    TClose name ->
                        if name == skipTag then
                            filterHelp rest (skipDepth - 1) skipTag acc
                        else
                            filterHelp rest skipDepth skipTag acc

                    _ ->
                        filterHelp rest skipDepth skipTag acc

            else
                case tok of
                    TRaw ->
                        filterHelp rest 0 "" acc

                    TText s ->
                        filterHelp rest 0 "" (TText s :: acc)

                    TClose name ->
                        if Set.member name safeElements then
                            filterHelp rest 0 "" (TClose name :: acc)
                        else
                            filterHelp rest 0 "" acc

                    TOpen name attrs ->
                        if Set.member name rawTextElements then
                            filterHelp rest 1 name acc

                        else if Set.member name safeElements then
                            filterHelp rest 0 "" (TOpen name (filterAttrs attrs) :: acc)

                        else
                            -- Unknown element: drop the tag, keep text children
                            filterHelp rest 0 "" acc


filterAttrs : List Attr -> List Attr
filterAttrs =
    List.filterMap filterAttr


filterAttr : Attr -> Maybe Attr
filterAttr attr =
    if Set.member attr.name urlAttrs then
        if isSafeUrl attr.value then
            Just attr
        else
            Nothing

    else if Set.member attr.name safeGlobalAttrs then
        Just attr

    else
        Nothing


-- ── RENDERER ─────────────────────────────────────────────────────────────────

renderTokens : List Token -> String
renderTokens tokens =
    String.concat (List.map renderToken tokens)


renderToken : Token -> String
renderToken tok =
    case tok of
        TText s ->
            s

        TOpen name attrs ->
            "<" ++ name ++ renderAttrs attrs ++ ">"

        TClose name ->
            "</" ++ name ++ ">"

        TRaw ->
            ""


renderAttrs : List Attr -> String
renderAttrs attrs =
    if List.isEmpty attrs then
        ""
    else
        " " ++ String.join " " (List.map renderAttr attrs)


renderAttr : Attr -> String
renderAttr attr =
    if String.isEmpty attr.value then
        attr.name
    else
        attr.name ++ "=\"" ++ escapeAttrValue attr.value ++ "\""


escapeAttrValue : String -> String
escapeAttrValue s =
    s
        |> String.replace "&" "&amp;"
        |> String.replace "\"" "&quot;"
        |> String.replace "<" "&lt;"


-- ── TEXT EXTRACTION / HTML ENCODING ──────────────────────────────────────────

extractText : Token -> Maybe String
extractText tok =
    case tok of
        TText s ->
            Just s

        _ ->
            Nothing


htmlEncode : String -> String
htmlEncode s =
    s
        |> String.replace "&" "&amp;"
        |> String.replace "<" "&lt;"
        |> String.replace ">" "&gt;"
        |> String.replace "\"" "&quot;"
        |> String.replace "'" "&#x27;"


-- ── STRING UTILITIES ─────────────────────────────────────────────────────────

{-| Return (before-ch, from-ch-onward).  If `ch` is absent, returns (str, ""). -}
spanBefore : Char -> String -> ( String, String )
spanBefore ch str =
    case String.indexes (String.fromChar ch) str of
        [] ->
            ( str, "" )

        ( i :: _ ) ->
            ( String.left i str, String.dropLeft i str )


{-| Return (prefix-satisfying-pred, rest). -}
consumeWhile : (Char -> Bool) -> String -> ( String, String )
consumeWhile pred str =
    let
        n = countPrefix pred str
    in
    ( String.left n str, String.dropLeft n str )


countPrefix : (Char -> Bool) -> String -> Int
countPrefix pred str =
    let
        go chars n =
            case chars of
                [] ->
                    n

                ( c :: cs ) ->
                    if pred c then
                        go cs (n + 1)
                    else
                        n
    in
    go (String.toList str) 0


{-| Drop characters through and including the first occurrence of `ch`. -}
dropUntilAfter : Char -> String -> String
dropUntilAfter ch str =
    case String.indexes (String.fromChar ch) str of
        [] ->
            ""

        ( i :: _ ) ->
            String.dropLeft (i + 1) str


skipWs : String -> String
skipWs str =
    Tuple.second (consumeWhile isWhitespace str)


-- ── CHARACTER PREDICATES ─────────────────────────────────────────────────────

isNameStartChar : Char -> Bool
isNameStartChar c =
    Char.isAlpha c || c == '_' || c == ':'


isNameChar : Char -> Bool
isNameChar c =
    Char.isAlphaNum c || c == '_' || c == ':' || c == '-' || c == '.'


isAttrNameChar : Char -> Bool
isAttrNameChar c =
    not (isWhitespace c)
        && c /= '='
        && c /= '>'
        && c /= '/'
        && c /= '"'
        && c /= '\''
        && c /= '\u{0000}'


isUnquotedValueChar : Char -> Bool
isUnquotedValueChar c =
    not (isWhitespace c)
        && c /= '>'
        && c /= '"'
        && c /= '\''
        && c /= '`'
        && c /= '='


isWhitespace : Char -> Bool
isWhitespace c =
    c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\u{000C}'
