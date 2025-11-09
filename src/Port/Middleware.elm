port module Port.Middleware exposing
    ( SecurityPolicy(..)
    , send
    , sendString
    )

import Json.Encode as Encode exposing (Value)
import Regex

-- Single generic outgoing port
port sendToJS : { policy : String, data : Value } -> Cmd msg

-- Security policies
type SecurityPolicy
    = AllowTextOnly
    | AllowSafeHtml
    | AllowUrl
    | Passthrough

-- Encode policy for JS
policyToString : SecurityPolicy -> String
policyToString policy =
    case policy of
        AllowTextOnly -> "text-only"
        AllowSafeHtml -> "safe-html"
        AllowUrl -> "url"
        Passthrough -> "passthrough"

-- Sanitization engine
sanitize : SecurityPolicy -> String -> String
sanitize policy rawString =
    case policy of
        AllowTextOnly ->
            stripHtml rawString

        AllowSafeHtml ->
            stripScriptTags rawString

        AllowUrl ->
            if String.startsWith "javascript:" (String.toLower rawString) then
                ""
            else
                rawString

        Passthrough ->
            rawString

-- Helper functions
stripScriptTags : String -> String
stripScriptTags =
    Regex.replace
        (Regex.fromString "<script.*?</script>"
            |> Maybe.withDefault Regex.never
        )
        (\_ -> "")

stripHtml : String -> String
stripHtml =
    Regex.replace
        (Regex.fromString "<[^>]*>"
            |> Maybe.withDefault Regex.never
        )
        (\_ -> "")

-- Public API for sending strings
sendString : SecurityPolicy -> String -> Cmd msg
sendString policy rawString =
    let
        safeString =
            sanitize policy rawString
    in
    sendToJS
        { policy = policyToString policy
        , data = Encode.string safeString
        }

-- Public API for sending any JSON value
send : SecurityPolicy -> Value -> Cmd msg
send policy payload =
    sendToJS
        { policy = policyToString policy
        , data = payload
        }