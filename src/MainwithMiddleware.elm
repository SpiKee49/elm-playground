module Main exposing (main)

import Browser
import Html exposing (Html, button, div, input, text)
import Html.Attributes exposing (value)
import Html.Events exposing (onClick, onInput)
import Json.Encode as Encode
import Port.Middleware -- Importujeme náš nový middleware!


-- MODEL
type alias Model =
    { name : String
    , counter : Int
    }


initialModel : Model
initialModel =
    { name = "Používateľ", counter = 0 }


-- UPDATE
type Msg
    = UpdateName String
    | Increment
    | SaveData -- Toto je akcia, ktorá spustí porty


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UpdateName newName ->
            ( { model | name = newName }, Cmd.none )

        Increment ->
            ( { model | counter = model.counter + 1 }, Cmd.none )

        SaveData ->
            -- Tu je kúzlo! Používame náš middleware.
            -- Chceme poslať dve rôzne úlohy naraz.
            let
                -- 1. Úloha: Uložiť meno (použijeme `sendString`)
                saveNameCmd =
                    Port.Middleware.sendString "saveName" model.name

                -- 2. Úloha: Uložiť počítadlo (použijeme `sendInt`)
                saveCounterCmd =
                    Port.Middleware.sendInt "saveCounter" model.counter
                
                -- 3. Úloha: Poslať komplexný JSON objekt
                -- Ukážka použitia generickej `send` funkcie
                saveAllCmd =
                    Port.Middleware.send "saveAll"
                        (Encode.object
                            [ ( "username", Encode.string model.name )
                            , ( "clickCount", Encode.int model.counter )
                            ]
                        )

            in
            -- Spojíme všetky príkazy do jedného a pošleme ich
            ( model, Cmd.batch [ saveNameCmd, saveCounterCmd, saveAllCmd ] )


-- VIEW
view : Model -> Html Msg
view model =
    div []
        [ div [] [ text ("Počítadlo: " ++ String.fromInt model.counter) ]
        , button [ onClick Increment ] [ text "+" ]
        , div []
            [ text "Meno: "
            , input [ value model.name, onInput UpdateName ] []
            ]
        , button [ onClick SaveData ] [ text "Uložiť dáta (cez porty)" ]
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
