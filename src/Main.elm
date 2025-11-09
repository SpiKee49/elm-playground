module Main exposing (main)

import Browser
import Html exposing (Html, button, div, h3, input, text)
import Html.Attributes exposing (placeholder, style, value)
import Html.Events exposing (onClick, onInput)
import Json.Encode as Encode
import Port.Middleware as Port

-- MODEL
type alias Model =
    { plainText : String
    , richText : String
    , url : String
    , trustedData : String
    , counter : Int
    }

initialModel : Model
initialModel =
    { plainText = "Hello <script>alert('XSS')</script> World"
    , richText = "This is <b>bold</b> and <script>alert('XSS')</script>"
    , url = "javascript:alert('XSS')"
    , trustedData = "System generated data"
    , counter = 0
    }

-- UPDATE
type Msg
    = SetPlainText String
    | SetRichText String
    | SetUrl String
    | SetTrustedData String
    | Increment
    | SendPlainText
    | SendRichText
    | SendUrl
    | SendTrustedData
    | SendCounter

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        SetPlainText str ->
            ( { model | plainText = str }, Cmd.none )

        SetRichText str ->
            ( { model | richText = str }, Cmd.none )

        SetUrl str ->
            ( { model | url = str }, Cmd.none )

        SetTrustedData str ->
            ( { model | trustedData = str }, Cmd.none )

        Increment ->
            ( { model | counter = model.counter + 1 }, Cmd.none )

        SendPlainText ->
            ( model
            , Port.sendString Port.AllowTextOnly model.plainText
            )

        SendRichText ->
            ( model
            , Port.sendString Port.AllowSafeHtml model.richText
            )

        SendUrl ->
            ( model
            , Port.sendString Port.AllowUrl model.url
            )

        SendTrustedData ->
            ( model
            , Port.sendString Port.Passthrough model.trustedData
            )

        SendCounter ->
            ( model
            , Port.send Port.Passthrough (Encode.int model.counter)
            )

-- VIEW
view : Model -> Html Msg
view model =
    div [ style "padding" "20px", style "font-family" "sans-serif" ]
        [ h3 [] [ text "XSS Protection Demo - Security Policies" ]
        
        -- Policy 1: AllowTextOnly
        , div [ style "margin-bottom" "20px", style "border" "1px solid #ccc", style "padding" "10px" ]
            [ h3 [] [ text "1. AllowTextOnly Policy" ]
            , text "Strips ALL HTML tags"
            , div []
                [ input
                    [ placeholder "Enter text with HTML"
                    , value model.plainText
                    , onInput SetPlainText
                    , style "width" "400px"
                    ]
                    []
                , button [ onClick SendPlainText, style "margin-left" "10px" ] 
                    [ text "Send with AllowTextOnly" ]
                ]
            ]
        
        -- Policy 2: AllowSafeHtml
        , div [ style "margin-bottom" "20px", style "border" "1px solid #ccc", style "padding" "10px" ]
            [ h3 [] [ text "2. AllowSafeHtml Policy" ]
            , text "Strips dangerous tags (<script>) but keeps safe HTML (<b>, <i>)"
            , div []
                [ input
                    [ placeholder "Enter HTML content"
                    , value model.richText
                    , onInput SetRichText
                    , style "width" "400px"
                    ]
                    []
                , button [ onClick SendRichText, style "margin-left" "10px" ] 
                    [ text "Send with AllowSafeHtml" ]
                ]
            ]
        
        -- Policy 3: AllowUrl
        , div [ style "margin-bottom" "20px", style "border" "1px solid #ccc", style "padding" "10px" ]
            [ h3 [] [ text "3. AllowUrl Policy" ]
            , text "Blocks javascript: URLs"
            , div []
                [ input
                    [ placeholder "Enter URL"
                    , value model.url
                    , onInput SetUrl
                    , style "width" "400px"
                    ]
                    []
                , button [ onClick SendUrl, style "margin-left" "10px" ] 
                    [ text "Send with AllowUrl" ]
                ]
            ]
        
        -- Policy 4: Passthrough
        , div [ style "margin-bottom" "20px", style "border" "1px solid #ccc", style "padding" "10px" ]
            [ h3 [] [ text "4. Passthrough Policy (Trusted Data)" ]
            , text "No sanitization - use only for trusted data!"
            , div []
                [ input
                    [ placeholder "Trusted system data"
                    , value model.trustedData
                    , onInput SetTrustedData
                    , style "width" "400px"
                    ]
                    []
                , button [ onClick SendTrustedData, style "margin-left" "10px" ] 
                    [ text "Send with Passthrough" ]
                ]
            , div [ style "margin-top" "10px" ]
                [ text ("Counter: " ++ String.fromInt model.counter)
                , button [ onClick Increment, style "margin-left" "10px" ] [ text "+" ]
                , button [ onClick SendCounter, style "margin-left" "10px" ] 
                    [ text "Send Counter (Passthrough)" ]
                ]
            ]
        ]

-- SUBSCRIPTIONS
subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none

-- MAIN
main : Program () Model Msg
main =
    Browser.element
        { init = \() -> ( initialModel, Cmd.none )
        , view = view
        , update = update
        , subscriptions = subscriptions
        }