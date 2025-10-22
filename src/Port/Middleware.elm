port module Port.Middleware exposing
    ( 
      SecurityPolicy(..)
    , send
    , sendString

    -- The types of tasks JS can handle
    , TaskName(..)
    , encodeTaskName
    )

import Json.Encode as Encode exposing (Value)
import Regex


-- DEFINÍCIA PORTU (zostáva rovnaká)
-- This is the single, centralized exit point from Elm.
port sendTask : { taskName : String, payload : Value } -> Cmd msg


-- KROK 1: DEFINOVANIE BEZPEČNOSTNEJ POLITIKY
-- This type defines *how* data should be sanitized.
-- Your Elm code must choose a policy for every piece of data it sends.
type SecurityPolicy
    = AllowTextOnly
    -- ^ Strips all HTML. Use for names, numbers, simple text.
    
    | AllowSafeHtml
    -- ^ (Your engine will implement this)
    -- ^ Strips dangerous tags/attributes (`<script>`, `onerror`, etc.)
    -- ^ but allows safe ones (`<b>`, `<i>`, `<ul>`).
    
    | AllowUrl
    -- ^ (Your engine will implement this)
    -- ^ Validates a URL, ensuring it's not `javascript:` or malicious.
    
    | Passthrough
    -- ^ !!! DANGER !!!
    -- ^ Bypasses all sanitization. Use *only* for data you 100%
    -- ^ trust (e.g., an integer, a boolean, a system ID).


-- KROK 2: DEFINOVANIE NÁZVOV ÚLOH
-- This provides type-safe task names, so you can't make a typo.
type TaskName
    = SaveUsername
    | SaveCounter
    | UpdatePageTitle


-- Helper to convert the task name to the string JS expects
encodeTaskName : TaskName -> String
encodeTaskName task =
    case task of
        SaveUsername -> "saveUsername"
        SaveCounter -> "saveCounter"
        UpdatePageTitle -> "updatePageTitle"


-- KROK 3: SANITIZAČNÝ ENGINE
-- This is the "engine" from your schedule.
-- You will build this out with more advanced logic.
sanitize : SecurityPolicy -> String -> String
sanitize policy rawString =
    case policy of
        AllowTextOnly ->
            -- This is a basic implementation.
            -- A better one would use a more robust regex or parser.
            stripHtml rawString

        AllowSafeHtml ->
            -- This is where your main sanitization logic will go.
            -- For now, we'll just strip <script> tags as a demo.
            stripScriptTags rawString

        AllowUrl ->
            -- This is where you validate URLs.
            -- For now, we'll do a basic check for `javascript:`.
            if String.startsWith "javascript:" (String.toLower rawString) then
                "" -- Block dangerous URLs
            else
                rawString

        Passthrough ->
            -- No sanitization. The data is sent as-is.
            rawString


-- Helpers for the engine (you will make these much better)
stripScriptTags : String -> String
stripScriptTags =
    Regex.replace (Regex.fromString "<script.*?</script>" |> Result.withDefault Regex.never)
        (\_ -> "")

stripHtml : String -> String
stripHtml =
    Regex.replace (Regex.fromString "<[^>]*>" |> Result.withDefault Regex.never)
        (\_ -> "")


-- KROK 4: FUNKCIE NA ODOSIELANIE DÁT
-- These are the public functions your app will use.

-- | The main function for sending any JSON `Value`.
-- | It's marked "Passthrough" by default, so it's best to use
-- | the more specific helpers like `sendString`.
send : TaskName -> SecurityPolicy -> Value -> Cmd msg
send task policy payload =
    let
        -- Here, if the policy wasn't Passthrough, you might
        -- try to sanitize the JSON, but that's complex.
        -- This architecture works best for sending simple values.
        -- We'll assume `send` is for trusted, pre-encoded data.
        _ = policy -- We're not using the policy here, just demonstrating
    in
    sendTask
        { taskName = encodeTaskName task
        , payload = payload
        }


-- | The primary function for sending string data.
-- | It *forces* you to choose a policy.
-- | It sanitizes the string *before* encoding and sending it.
sendString : TaskName -> SecurityPolicy -> String -> Cmd msg
sendString task policy rawString =
    let
        -- SANITIZATION HAPPENS HERE!
        safeString =
            sanitize policy rawString
    in
    sendTask
        { taskName = encodeTaskName task
        , payload = Encode.string safeString
        }