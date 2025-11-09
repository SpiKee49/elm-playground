module Main exposing (..)

import Browser
import Html exposing (Html, button, div, input, text)
import Html.Attributes exposing (placeholder, value)
import Html.Events exposing (onClick, onInput)
import Json.Encode as Encode
import Port.Middleware as Port


-- MODEL
type alias Model =
    { username : String -- User-provided, potentially unsafe
    , comment : String -- User-provided, potentially unsafe
    , counter : Int
    }

initialModel : Model 
initialModel =
    { username = "Jano <script>alert(1)</script>"
    , comment = "This is <b>bold</b> and this is <script>alert(2)</script>"
    , counter = 0
    }

-- UPDATE
type Msg
    = SetUsername String
    | SetComment String
    | Increment
    | Save


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        SetUsername str ->
            ( { model | username = str }, Cmd.none )

        SetComment str ->
            ( { model | comment = str }, Cmd.none )

        Increment ->
            ( { model | counter = model.counter + 1 }, Cmd.none )

        Save ->
            let
                -- 1. Chceme uložiť meno. Povolíme iba čistý text.
                saveUserCmd =
                    Port.sendString Port.SaveUsername Port.AllowTextOnly model.username
                
                -- 2. Chceme uložiť komentár. Povolíme "bezpečné" HTML.
                saveCommentCmd =
                    Port.sendString Port.SaveUsername Port.AllowSafeHtml model.comment

                -- 3. Chceme uložiť počítadlo. Je to Int,
                --    takže je bezpečné ho poslať priamo.
                saveCountCmd =
                    Port.send Port.SaveCounter Port.Passthrough (Encode.int model.counter)
            in
            ( model, Cmd.batch [ saveUserCmd, saveCommentCmd, saveCountCmd ] )


-- VIEW
view : Model -> Html Msg
view model =
    div []
        [ div []
            [ text "Username: "
            , input [ placeholder "Your name", value model.username, onInput SetUsername ] []
            ]
        , button [ onClick Save ] [ text "Save to JS" ]
        ]

-- MAIN
main : Program () Model Msg
main =
    Browser.element
        { init = \() -> ( initialModel, Cmd.none )
        , view = view
        , update = update
        , subscriptions = \_ -> Sub.none
        }