module Main exposing (main)

import Browser
import Html exposing (..)
import Html.Attributes exposing (class, href, placeholder, style, value)
import Html.Events exposing (onClick, onInput)
import Json.Encode as Encode
import Port.Middleware as Port
import Tests exposing (TestResult, runAllTests)


-- MODEL

type alias Model =
    { plainText : String
    , richText  : String
    , url       : String
    , counter   : Int
    , activeTab : Tab
    }


type Tab
    = DemoTab
    | TestsTab


initialModel : Model
initialModel =
    { plainText = "Hello <script>alert('XSS')</script> World"
    , richText  = "This is <b>bold</b> and <script>alert('XSS')</script>"
    , url       = "javascript:alert('XSS')"
    , counter   = 0
    , activeTab = DemoTab
    }


-- UPDATE

type Msg
    = UpdatePlainText String
    | UpdateRichText String
    | UpdateUrl String
    | IncrementCounter
    | SendPlainText
    | SendRichText
    | SendUrl
    | SendCounter
    | SetTab Tab


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UpdatePlainText str  -> ( { model | plainText = str }, Cmd.none )
        UpdateRichText  str  -> ( { model | richText  = str }, Cmd.none )
        UpdateUrl       str  -> ( { model | url       = str }, Cmd.none )
        IncrementCounter     -> ( { model | counter   = model.counter + 1 }, Cmd.none )
        SetTab tab           -> ( { model | activeTab = tab }, Cmd.none )
        SendPlainText        -> ( model, Port.sendString Port.AllowTextOnly model.plainText )
        SendRichText         -> ( model, Port.sendString Port.AllowSafeHtml model.richText )
        SendUrl              -> ( model, Port.sendString Port.AllowUrl model.url )
        SendCounter          -> ( model, Port.send Port.Passthrough (Encode.int model.counter) )


-- VIEW

view : Model -> Html Msg
view model =
    div [ style "font-family" "system-ui, sans-serif"
        , style "max-width" "900px"
        , style "margin" "0 auto"
        , style "padding" "24px"
        , style "color" "#1a1a1a"
        ]
        [ -- Header
          h1 [ style "font-size" "1.4rem"
             , style "font-weight" "700"
             , style "margin-bottom" "4px"
             , style "color" "#111"
             ]
             [ text "Elm XSS Protection — Port Middleware Demo" ]
        , p [ style "color" "#555"
            , style "margin-top" "0"
            , style "margin-bottom" "20px"
            , style "font-size" "0.9rem"
            ]
            [ text "Proof-of-concept library demonstrating compile-time policy enforcement at the Elm → JavaScript port boundary." ]

        -- Tab bar
        , div [ style "display" "flex"
              , style "gap" "4px"
              , style "margin-bottom" "24px"
              , style "border-bottom" "2px solid #e0e0e0"
              ]
              [ tabButton DemoTab  "Interactive Demo" model.activeTab
              , tabButton TestsTab "Test Suite"       model.activeTab
              ]

        -- Tab content
        , case model.activeTab of
            DemoTab  -> viewDemo  model
            TestsTab -> viewTests runAllTests
        ]


tabButton : Tab -> String -> Tab -> Html Msg
tabButton tab label activeTab =
    let
        isActive = tab == activeTab
        activeStyles =
            [ style "border-bottom" "2px solid #2563eb"
            , style "color" "#2563eb"
            , style "margin-bottom" "-2px"
            ]
        baseStyles =
            [ style "background" "none"
            , style "border" "none"
            , style "padding" "8px 16px"
            , style "cursor" "pointer"
            , style "font-size" "0.9rem"
            , style "font-weight" "600"
            , style "color" "#666"
            ]
    in
    button
        (baseStyles ++ (if isActive then activeStyles else []) ++ [ onClick (SetTab tab) ])
        [ text label ]


-- ─── DEMO TAB ─────────────────────────────────────────────────────────────────

viewDemo : Model -> Html Msg
viewDemo model =
    div []
        [ policyCard "1" "AllowTextOnly" "#dc2626"
            "Strips ALL HTML tags and escapes special characters. Output is always safe plain text."
            [ demoInput "Enter text (try XSS payloads)" model.plainText UpdatePlainText
            , demoButton "Send with AllowTextOnly" SendPlainText "#dc2626"
            ]
        , policyCard "2" "AllowSafeHtml" "#d97706"
            "Removes <script>, dangerous tags (iframe, svg, object…), and all event handlers. Preserves safe markup like <b>, <i>, <p>."
            [ demoInput "Enter HTML content" model.richText UpdateRichText
            , demoButton "Send with AllowSafeHtml" SendRichText "#d97706"
            ]
        , policyCard "3" "AllowUrl" "#2563eb"
            "Blocks javascript:, data:, vbscript: schemes and obfuscated variants (tab/newline/null-byte injection, entity-encoded starts). Returns empty string if blocked."
            [ demoInput "Enter URL" model.url UpdateUrl
            , demoButton "Send with AllowUrl" SendUrl "#2563eb"
            ]
        , policyCard "4" "Passthrough" "#16a34a"
            "No sanitization. Use only for internally generated, trusted values — never for user input."
            [ div [ style "display" "flex", style "align-items" "center", style "gap" "12px" ]
                [ span [ style "font-size" "1rem" ]
                    [ text ("Counter: " ++ String.fromInt model.counter) ]
                , demoButton "+" IncrementCounter "#16a34a"
                , demoButton "Send Counter (Passthrough)" SendCounter "#16a34a"
                ]
            ]
        ]


policyCard : String -> String -> String -> String -> List (Html Msg) -> Html Msg
policyCard number policyName color description children =
    div [ style "border" ("1px solid " ++ color)
        , style "border-radius" "8px"
        , style "padding" "16px"
        , style "margin-bottom" "16px"
        ]
        [ div [ style "display" "flex", style "align-items" "center", style "gap" "10px", style "margin-bottom" "8px" ]
            [ span [ style "background" color
                   , style "color" "white"
                   , style "border-radius" "50%"
                   , style "width" "24px"
                   , style "height" "24px"
                   , style "display" "inline-flex"
                   , style "align-items" "center"
                   , style "justify-content" "center"
                   , style "font-size" "0.8rem"
                   , style "font-weight" "700"
                   , style "flex-shrink" "0"
                   ]
                   [ text number ]
            , h3 [ style "margin" "0", style "font-size" "1rem", style "color" color ]
                [ text policyName ]
            ]
        , p [ style "margin" "0 0 12px"
            , style "font-size" "0.85rem"
            , style "color" "#555"
            , style "line-height" "1.5"
            ]
            [ text description ]
        , div [] children
        ]


demoInput : String -> String -> (String -> Msg) -> Html Msg
demoInput ph val handler =
    input
        [ placeholder ph
        , value val
        , onInput handler
        , style "width" "100%"
        , style "box-sizing" "border-box"
        , style "padding" "8px 10px"
        , style "border" "1px solid #ccc"
        , style "border-radius" "4px"
        , style "font-size" "0.9rem"
        , style "margin-bottom" "8px"
        , style "font-family" "monospace"
        ]
        []


demoButton : String -> Msg -> String -> Html Msg
demoButton label msg color =
    button
        [ onClick msg
        , style "background" color
        , style "color" "white"
        , style "border" "none"
        , style "padding" "8px 14px"
        , style "border-radius" "4px"
        , style "cursor" "pointer"
        , style "font-size" "0.85rem"
        , style "font-weight" "600"
        ]
        [ text label ]


-- ─── TEST SUITE TAB ───────────────────────────────────────────────────────────

viewTests : List TestResult -> Html Msg
viewTests results =
    let
        passed = Tests.passCount results
        failed = Tests.failCount results
        total  = List.length results
    in
    div []
        [ -- Summary bar
          div [ style "display" "flex"
              , style "align-items" "center"
              , style "gap" "16px"
              , style "padding" "12px 16px"
              , style "background" (if failed == 0 then "#f0fdf4" else "#fef2f2")
              , style "border" ("1px solid " ++ (if failed == 0 then "#bbf7d0" else "#fecaca"))
              , style "border-radius" "8px"
              , style "margin-bottom" "20px"
              ]
              [ span [ style "font-weight" "700", style "font-size" "1rem" ]
                    [ text (if failed == 0 then "All tests passing" else "Some tests failing") ]
              , badge (String.fromInt passed ++ " passed") "#16a34a"
              , badge (String.fromInt failed ++ " failed") (if failed == 0 then "#9ca3af" else "#dc2626")
              , span [ style "color" "#555", style "font-size" "0.85rem" ]
                    [ text (String.fromInt total ++ " total") ]
              ]

        -- Group by category
        , div [] (viewTestGroups results)
        ]


badge : String -> String -> Html Msg
badge label color =
    span [ style "background" color
         , style "color" "white"
         , style "padding" "2px 10px"
         , style "border-radius" "99px"
         , style "font-size" "0.8rem"
         , style "font-weight" "600"
         ]
         [ text label ]


viewTestGroups : List TestResult -> List (Html Msg)
viewTestGroups results =
    let
        categories = [ "AllowTextOnly", "AllowSafeHtml", "AllowUrl" ]
    in
    List.map (\cat -> viewTestGroup cat (List.filter (\r -> r.testCase.category == cat) results)) categories


viewTestGroup : String -> List TestResult -> Html Msg
viewTestGroup category results =
    let
        passed = Tests.passCount results
        total  = List.length results
        color  =
            case category of
                "AllowTextOnly" -> "#dc2626"
                "AllowSafeHtml" -> "#d97706"
                "AllowUrl"      -> "#2563eb"
                _               -> "#555"
    in
    div [ style "margin-bottom" "24px" ]
        [ div [ style "display" "flex"
              , style "align-items" "center"
              , style "gap" "10px"
              , style "margin-bottom" "8px"
              ]
              [ h3 [ style "margin" "0", style "font-size" "0.95rem", style "color" color ]
                   [ text category ]
              , span [ style "font-size" "0.8rem", style "color" "#555" ]
                    [ text (String.fromInt passed ++ "/" ++ String.fromInt total) ]
              ]
        , div [] (List.map viewTestRow results)
        ]


viewTestRow : TestResult -> Html Msg
viewTestRow result =
    let
        passColor = if result.passed then "#f0fdf4" else "#fef2f2"
        borderColor = if result.passed then "#bbf7d0" else "#fecaca"
        icon = if result.passed then "PASS" else "FAIL"
        iconColor = if result.passed then "#16a34a" else "#dc2626"
    in
    div [ style "border" ("1px solid " ++ borderColor)
        , style "border-radius" "6px"
        , style "padding" "10px 12px"
        , style "margin-bottom" "6px"
        , style "background" passColor
        ]
        [ div [ style "display" "flex", style "align-items" "flex-start", style "gap" "10px" ]
            [ span [ style "font-size" "0.72rem"
                   , style "font-weight" "700"
                   , style "color" iconColor
                   , style "flex-shrink" "0"
                   , style "margin-top" "2px"
                   , style "background" (if result.passed then "#dcfce7" else "#fee2e2")
                   , style "padding" "1px 6px"
                   , style "border-radius" "3px"
                   ]
                   [ text icon ]
            , div [ style "flex" "1", style "min-width" "0" ]
                [ div [ style "font-size" "0.88rem", style "font-weight" "600", style "margin-bottom" "4px" ]
                      [ text result.testCase.description ]
                , div [ style "display" "flex", style "gap" "8px", style "flex-wrap" "wrap" ]
                    [ codeSnippet "IN"  result.testCase.input
                    , codeSnippet "OUT" result.output
                    ]
                , if not result.passed then
                    div [ style "margin-top" "6px" ]
                        (List.map (\f -> div [ style "font-size" "0.8rem", style "color" "#dc2626" ] [ text ("  * " ++ f) ]) result.failures)
                  else
                    text ""
                ]
            ]
        ]


codeSnippet : String -> String -> Html Msg
codeSnippet label content =
    div [ style "display" "flex", style "align-items" "baseline", style "gap" "4px" ]
        [ span [ style "font-size" "0.72rem"
               , style "font-weight" "600"
               , style "color" "#666"
               , style "flex-shrink" "0"
               ]
               [ text (label ++ ":") ]
        , span [ style "font-family" "monospace"
               , style "font-size" "0.78rem"
               , style "color" "#333"
               , style "word-break" "break-all"
               , style "max-width" "380px"
               ]
               [ text (truncate 80 content) ]
        ]


truncate : Int -> String -> String
truncate maxLen s =
    if String.length s > maxLen then
        String.left maxLen s ++ "…"
    else
        s


-- SUBSCRIPTIONS / MAIN

subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none


main : Program () Model Msg
main =
    Browser.element
        { init = \() -> ( initialModel, Cmd.none )
        , view = view
        , update = update
        , subscriptions = subscriptions
        }
