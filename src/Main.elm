module Main exposing (main)

import Browser
import Dict
import Html exposing (..)
import Html.Attributes exposing (class, href, placeholder, style, value)
import Html.Events exposing (onClick, onInput)
import Json.Encode as Encode
import Port.Middleware as Port
import Tests exposing (TestResult, runAllTests)


-- MODEL

type alias Model =
    { plainText          : String
    , richText           : String
    , url                : String
    , passthroughText    : String
    , activeTab          : Tab
    , comparisonResults  : List ComparisonResult
    , comparisonPending  : Bool
    }


type Tab
    = DemoTab
    | TestsTab
    | ComparisonTab


type alias ComparisonResult =
    { id          : String
    , category    : String
    , input       : String
    , elmTextOnly : String
    , elmSafeHtml : String
    , dpTextOnly  : String
    , dpSafeHtml  : String
    }


initialModel : Model
initialModel =
    { plainText         = "Hello <script>alert('XSS')</script> World"
    , richText          = "This is <b>bold</b> and <script>alert('XSS')</script>"
    , url               = "javascript:alert('XSS')"
    , passthroughText   = "trusted internal value"
    , activeTab         = DemoTab
    , comparisonResults = []
    , comparisonPending = False
    }


-- UPDATE

type Msg
    = UpdatePlainText String
    | UpdateRichText String
    | UpdateUrl String
    | UpdatePassthrough String
    | SendPlainText
    | SendRichText
    | SendUrl
    | SendPassThrough
    | SetTab Tab
    | GotComparisonResults (List { id : String, textOnly : String, safeHtml : String })


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UpdatePlainText str   -> ( { model | plainText = str }, Cmd.none )
        UpdateRichText  str   -> ( { model | richText  = str }, Cmd.none )
        UpdateUrl         str -> ( { model | url             = str }, Cmd.none )
        UpdatePassthrough str -> ( { model | passthroughText = str }, Cmd.none )
        SendPlainText         -> ( model, Port.sendString Port.AllowTextOnly model.plainText )
        SendRichText          -> ( model, Port.sendString Port.AllowSafeHtml model.richText )
        SendUrl               -> ( model, Port.sendString Port.AllowUrl model.url )
        SendPassThrough       -> ( model, Port.send Port.Passthrough (Encode.string model.passthroughText) )

        SetTab ComparisonTab ->
            let
                payloads = Tests.comparisonPayloads
                elmResults =
                    List.map
                        (\p ->
                            { id          = p.id
                            , category    = p.category
                            , input       = p.input
                            , elmTextOnly = Port.sanitize Port.AllowTextOnly p.input
                            , elmSafeHtml = Port.sanitize Port.AllowSafeHtml p.input
                            , dpTextOnly  = ""
                            , dpSafeHtml  = ""
                            })
                        payloads
                portPayloads =
                    List.map (\p -> { id = p.id, input = p.input }) payloads
            in
            ( { model | activeTab = ComparisonTab, comparisonResults = elmResults, comparisonPending = True }
            , Port.requestComparison portPayloads
            )

        SetTab tab ->
            ( { model | activeTab = tab }, Cmd.none )

        GotComparisonResults dpResults ->
            let
                dpDict =
                    Dict.fromList (List.map (\r -> ( r.id, r )) dpResults)
                updated =
                    List.map
                        (\r ->
                            case Dict.get r.id dpDict of
                                Just dp -> { r | dpTextOnly = dp.textOnly, dpSafeHtml = dp.safeHtml }
                                Nothing -> r
                        )
                        model.comparisonResults
            in
            ( { model | comparisonResults = updated, comparisonPending = False }, Cmd.none )


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
              [ tabButton DemoTab       "Interactive Demo" model.activeTab
              , tabButton TestsTab      "Test Suite"       model.activeTab
              , tabButton ComparisonTab "Comparison"       model.activeTab
              ]

        -- Tab content
        , case model.activeTab of
            DemoTab       -> viewDemo  model
            TestsTab      -> viewTests runAllTests
            ComparisonTab -> viewComparison model
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
            [ demoInput "Enter trusted value" model.passthroughText UpdatePassthrough
            , demoButton "Send with Passthrough" SendPassThrough "#16a34a"
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


-- ─── CONFUSION MATRIX & METRICS ──────────────────────────────────────────────
-- Axes:
--   Row    — did Elm change the input?  (elmOutput /= input)
--   Column — do the outputs agree?      (elmOutput == dpOutput)
--
-- This ensures TP + TN = matched rows and FP + FN = diverged rows,
-- consistent with what is visible in the comparison table.
--
-- Interpretation (DOMPurify = reference):
--   TP  Elm blocked, outputs identical   → Elm replicated DP exactly
--   FP  Elm blocked, outputs differ      → Elm blocked differently from DP
--                                           (over-blocking OR different encoding)
--   FN  Elm passed,  outputs differ      → DP blocked something Elm missed
--   TN  Elm passed,  outputs identical   → both left the input unchanged

type alias ConfusionMatrix =
    { tp : Int
    , fp : Int
    , fn : Int
    , tn : Int
    }


computeMatrix : List { category : String, input : String, elmOutput : String, dpOutput : String } -> ConfusionMatrix
computeMatrix rows =
    List.foldl
        (\r acc ->
            let
                elmBlocked   = r.elmOutput /= r.input
                outputsMatch = r.elmOutput == r.dpOutput
            in
            if elmBlocked && outputsMatch then
                { acc | tp = acc.tp + 1 }
            else if elmBlocked && not outputsMatch then
                { acc | fp = acc.fp + 1 }
            else if not elmBlocked && not outputsMatch then
                { acc | fn = acc.fn + 1 }
            else
                { acc | tn = acc.tn + 1 }
        )
        { tp = 0, fp = 0, fn = 0, tn = 0 }
        rows


computePrecision : ConfusionMatrix -> Maybe Float
computePrecision m =
    if m.tp + m.fp == 0 then Nothing
    else Just (toFloat m.tp / toFloat (m.tp + m.fp))


computeRecall : ConfusionMatrix -> Maybe Float
computeRecall m =
    if m.tp + m.fn == 0 then Nothing
    else Just (toFloat m.tp / toFloat (m.tp + m.fn))


computeF1 : ConfusionMatrix -> Maybe Float
computeF1 m =
    case ( computePrecision m, computeRecall m ) of
        ( Just p, Just r ) ->
            if p + r == 0 then Nothing
            else Just (2 * p * r / (p + r))
        _ ->
            Nothing


formatPct : Maybe Float -> String
formatPct mf =
    case mf of
        Nothing -> "N/A"
        Just f  ->
            let
                pct = f * 100
                intPart = floor pct
                frac = round ((pct - toFloat intPart) * 10)
            in
            String.fromInt intPart ++ "." ++ String.fromInt frac ++ "%"


-- ─── COMPARISON TAB ───────────────────────────────────────────────────────────

viewComparison : Model -> Html Msg
viewComparison model =
    if model.comparisonPending then
        div [ style "padding" "48px", style "text-align" "center", style "color" "#555" ]
            [ div [ style "font-size" "1rem", style "margin-bottom" "8px" ] [ text "Running DOMPurify comparison…" ]
            , div [ style "font-size" "0.85rem", style "color" "#888" ] [ text "Waiting for JavaScript port response." ]
            ]
    else if List.isEmpty model.comparisonResults then
        div [ style "padding" "48px", style "text-align" "center", style "color" "#888" ]
            [ text "Switch to this tab to run the comparison." ]
    else
        div []
            [ viewComparisonNote
            , viewComparisonSection
                "AllowTextOnly  vs  DOMPurify { ALLOWED_TAGS: [] }"
                "#dc2626"
                "Note: Elm HTML-escapes the remaining text (safe for innerHTML). DOMPurify returns plain text (safe for textContent). Differences in output format are expected even when both sanitizers neutralize the same threat."
                (List.map (\r -> { category = r.category, input = r.input, elmOutput = r.elmTextOnly, dpOutput = r.dpTextOnly }) model.comparisonResults)
            , viewComparisonSection
                "AllowSafeHtml  vs  DOMPurify default config"
                "#d97706"
                "Both aim to preserve safe HTML while stripping dangerous constructs. Divergences here reveal genuine policy gaps — payloads that one library blocks and the other passes."
                (List.map (\r -> { category = r.category, input = r.input, elmOutput = r.elmSafeHtml, dpOutput = r.dpSafeHtml }) model.comparisonResults)
            ]


viewComparisonNote : Html Msg
viewComparisonNote =
    div [ style "background" "#f0f9ff"
        , style "border" "1px solid #bae6fd"
        , style "border-radius" "8px"
        , style "padding" "12px 16px"
        , style "margin-bottom" "24px"
        , style "font-size" "0.85rem"
        , style "color" "#0c4a6e"
        , style "line-height" "1.5"
        ]
        [ text "85 curated XSS payloads from OWASP, PortSwigger, and mXSS research — run through both sanitizers. "
        , text "\"Match\" means the sanitized output strings are identical. "
        , text "Divergences in AllowSafeHtml vs DOMPurify reveal coverage gaps between the regex-based Elm approach and DOMPurify's DOM-parser-based sanitization."
        ]


viewComparisonSection :
    String
    -> String
    -> String
    -> List { category : String, input : String, elmOutput : String, dpOutput : String }
    -> Html Msg
viewComparisonSection title color note rows =
    let
        total        = List.length rows
        matchCount   = List.length (List.filter (\r -> r.elmOutput == r.dpOutput) rows)
        divergeCount = total - matchCount
        matrix       = computeMatrix rows
    in
    div [ style "margin-bottom" "40px" ]
        [ -- Section header
          div [ style "display" "flex"
              , style "align-items" "center"
              , style "flex-wrap" "wrap"
              , style "gap" "10px"
              , style "margin-bottom" "6px"
              ]
              [ h3 [ style "margin" "0", style "font-size" "0.95rem", style "color" color ] [ text title ]
              , badge (String.fromInt matchCount ++ " match") "#16a34a"
              , badge (String.fromInt divergeCount ++ " diverge") (if divergeCount == 0 then "#9ca3af" else "#d97706")
              ]
        , p [ style "font-size" "0.8rem", style "color" "#666", style "margin" "0 0 14px" ] [ text note ]
        -- Metrics panel
        , viewMetricsPanel matrix
        -- Table
        , div [ style "overflow-x" "auto", style "margin-top" "16px" ]
            [ table
                [ style "width" "100%"
                , style "border-collapse" "collapse"
                , style "font-size" "0.78rem"
                ]
                [ thead []
                    [ tr [ style "background" "#f8f9fa" ]
                        [ th (thStyle "120px" "left")   [ text "Category" ]
                        , th (thStyle "220px" "left")   [ text "Input" ]
                        , th (thStyle "220px" "left")   [ text "Elm output" ]
                        , th (thStyle "220px" "left")   [ text "DOMPurify output" ]
                        , th (thStyle "52px"  "center") [ text "Match" ]
                        ]
                    ]
                , tbody [] (List.map viewComparisonRow rows)
                ]
            ]
        ]


viewMetricsPanel : ConfusionMatrix -> Html Msg
viewMetricsPanel m =
    let
        prec = computePrecision m
        rec  = computeRecall m
        f1   = computeF1 m
    in
    div [ style "display" "flex"
        , style "gap" "20px"
        , style "flex-wrap" "wrap"
        , style "align-items" "flex-start"
        , style "padding" "14px"
        , style "background" "#f8f9fa"
        , style "border" "1px solid #e0e0e0"
        , style "border-radius" "8px"
        ]
        [ viewConfusionMatrix m
        , div [ style "display" "flex", style "flex-direction" "column", style "gap" "8px", style "justify-content" "flex-start" ]
            [ div [ style "font-size" "0.78rem", style "font-weight" "600", style "color" "#444", style "margin-bottom" "2px" ]
                [ text "Metrics (DOMPurify = ground truth)" ]
            , div [ style "display" "flex", style "gap" "10px", style "flex-wrap" "wrap" ]
                [ viewMetricCard "Precision" (formatPct prec) "TP / (TP+FP)" "Of Elm's blocks, what fraction produced the exact same output as DOMPurify."
                , viewMetricCard "Recall"    (formatPct rec)  "TP / (TP+FN)" "Of cases where outputs differed, what fraction did Elm block with matching output."
                , viewMetricCard "F1 Score"  (formatPct f1)   "2·P·R / (P+R)" "Harmonic mean of precision and recall."
                ]
            ]
        ]


viewConfusionMatrix : ConfusionMatrix -> Html Msg
viewConfusionMatrix m =
    div []
        [ div [ style "font-size" "0.78rem", style "font-weight" "600", style "color" "#444", style "margin-bottom" "6px" ]
            [ text "Confusion matrix" ]
        , table [ style "border-collapse" "collapse", style "font-size" "0.8rem" ]
            [ thead []
                [ tr []
                    [ th [ style "padding" "5px 12px", style "background" "#eee", style "border" "1px solid #ccc" ] [ text "" ]
                    , th [ style "padding" "5px 12px", style "background" "#eee", style "border" "1px solid #ccc", style "text-align" "center", style "color" "#555", style "white-space" "nowrap" ] [ text "outputs match" ]
                    , th [ style "padding" "5px 12px", style "background" "#eee", style "border" "1px solid #ccc", style "text-align" "center", style "color" "#555", style "white-space" "nowrap" ] [ text "outputs differ" ]
                    ]
                ]
            , tbody []
                [ tr []
                    [ td [ style "padding" "7px 12px", style "font-weight" "600", style "background" "#eee", style "border" "1px solid #ccc", style "white-space" "nowrap", style "color" "#555" ] [ text "Elm blocked" ]
                    , td [ style "padding" "7px 20px", style "text-align" "center", style "border" "1px solid #ccc", style "background" "#dcfce7" ]
                        [ div [ style "font-weight" "700", style "font-size" "1.1rem", style "color" "#16a34a" ] [ text (String.fromInt m.tp) ]
                        , div [ style "font-size" "0.68rem", style "color" "#6b7280" ] [ text "TP" ]
                        ]
                    , td [ style "padding" "7px 20px", style "text-align" "center", style "border" "1px solid #ccc", style "background" "#fee2e2" ]
                        [ div [ style "font-weight" "700", style "font-size" "1.1rem", style "color" "#dc2626" ] [ text (String.fromInt m.fp) ]
                        , div [ style "font-size" "0.68rem", style "color" "#6b7280" ] [ text "FP" ]
                        ]
                    ]
                , tr []
                    [ td [ style "padding" "7px 12px", style "font-weight" "600", style "background" "#eee", style "border" "1px solid #ccc", style "white-space" "nowrap", style "color" "#555" ] [ text "Elm passed" ]
                    , td [ style "padding" "7px 20px", style "text-align" "center", style "border" "1px solid #ccc", style "background" "#dcfce7" ]
                        [ div [ style "font-weight" "700", style "font-size" "1.1rem", style "color" "#16a34a" ] [ text (String.fromInt m.tn) ]
                        , div [ style "font-size" "0.68rem", style "color" "#6b7280" ] [ text "TN" ]
                        ]
                    , td [ style "padding" "7px 20px", style "text-align" "center", style "border" "1px solid #ccc", style "background" "#fef9c3" ]
                        [ div [ style "font-weight" "700", style "font-size" "1.1rem", style "color" "#d97706" ] [ text (String.fromInt m.fn) ]
                        , div [ style "font-size" "0.68rem", style "color" "#6b7280" ] [ text "FN" ]
                        ]
                    ]
                ]
            ]
        ]


viewMetricCard : String -> String -> String -> String -> Html Msg
viewMetricCard name value formula description =
    div [ style "border" "1px solid #e0e0e0"
        , style "border-radius" "8px"
        , style "padding" "10px 14px"
        , style "min-width" "100px"
        , style "background" "white"
        ]
        [ div [ style "font-size" "0.74rem", style "font-weight" "600", style "color" "#666", style "margin-bottom" "2px" ] [ text name ]
        , div [ style "font-size" "1.5rem", style "font-weight" "700", style "color" "#1a1a1a", style "line-height" "1.2" ] [ text value ]
        , div [ style "font-size" "0.68rem", style "color" "#888", style "margin-top" "3px", style "font-family" "monospace" ] [ text formula ]
        , div [ style "font-size" "0.7rem", style "color" "#999", style "margin-top" "4px", style "max-width" "120px", style "line-height" "1.3" ] [ text description ]
        ]


thStyle : String -> String -> List (Attribute Msg)
thStyle w align =
    [ style "padding" "7px 10px"
    , style "text-align" align
    , style "color" "#444"
    , style "font-weight" "600"
    , style "border-bottom" "2px solid #e0e0e0"
    , style "white-space" "nowrap"
    , style "min-width" w
    ]


viewComparisonRow : { category : String, input : String, elmOutput : String, dpOutput : String } -> Html Msg
viewComparisonRow row =
    let
        matches  = row.elmOutput == row.dpOutput
        rowBg    = if matches then "white" else "#fffbeb"
        borderBt = "1px solid #f0f0f0"
    in
    tr [ style "background" rowBg, style "border-bottom" borderBt ]
        [ td [ style "padding" "5px 10px", style "color" "#666", style "white-space" "nowrap", style "font-size" "0.74rem" ]
            [ text row.category ]
        , td [ style "padding" "5px 10px", style "font-family" "monospace", style "max-width" "220px" ]
            [ span [ style "display" "block"
                   , style "overflow" "hidden"
                   , style "text-overflow" "ellipsis"
                   , style "white-space" "nowrap"
                   , style "color" "#555"
                   ]
                   [ text (truncate 45 row.input) ]
            ]
        , td [ style "padding" "5px 10px", style "font-family" "monospace", style "max-width" "220px" ]
            [ span [ style "display" "block"
                   , style "overflow" "hidden"
                   , style "text-overflow" "ellipsis"
                   , style "white-space" "nowrap"
                   , style "color" "#333"
                   ]
                   [ text (if String.isEmpty row.elmOutput then "(empty)" else truncate 45 row.elmOutput) ]
            ]
        , td [ style "padding" "5px 10px", style "font-family" "monospace", style "max-width" "220px" ]
            [ span [ style "display" "block"
                   , style "overflow" "hidden"
                   , style "text-overflow" "ellipsis"
                   , style "white-space" "nowrap"
                   , style "color" "#333"
                   ]
                   [ text (if String.isEmpty row.dpOutput then "(empty)" else truncate 45 row.dpOutput) ]
            ]
        , td [ style "padding" "5px 10px", style "text-align" "center" ]
            [ if matches then
                span [ style "color" "#16a34a", style "font-weight" "700", style "font-size" "1rem" ] [ text "=" ]
              else
                span [ style "color" "#d97706", style "font-weight" "700", style "font-size" "1rem" ] [ text "≠" ]
            ]
        ]


-- SUBSCRIPTIONS / MAIN

subscriptions : Model -> Sub Msg
subscriptions _ =
    Port.receiveComparison GotComparisonResults


main : Program () Model Msg
main =
    Browser.element
        { init = \() -> ( initialModel, Cmd.none )
        , view = view
        , update = update
        , subscriptions = subscriptions
        }
