-- Musíme definovať modul ako "port module"
port module Main exposing (main)

import Browser
import Html exposing (Html, button, div, input, text)
import Html.Attributes exposing (placeholder, value)
import Html.Events exposing (onClick, onInput)
import Json.Decode as Decode

port saveName : String -> Cmd msg

port receiveName : (String -> msg) -> Sub msg


-- MODEL
type alias Model =
    { name : String
    }

initialModel : Model
initialModel =
    { name = "" }


-- UPDATE
type Msg
    = ChangeName String -- Keď používateľ píše do inputu
    | Save            -- Keď používateľ klikne na "Uložiť"
    | ReceivedName String -- Keď dostaneme meno z localStorage cez port


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        ChangeName newName ->
            ( { model | name = newName }, Cmd.none )

        Save ->
            -- Pošleme príkaz na náš odchádzajúci port s aktuálnym menom
            ( model, saveName model.name )

        ReceivedName nameFromJs ->
            -- Dostali sme meno z JS, tak aktualizujeme model
            ( { model | name = nameFromJs }, Cmd.none )


-- SUBSCRIPTIONS (PREDPLATNÉ)
subscriptions : Model -> Sub Msg
subscriptions model =
    receiveName ReceivedName


-- VIEW
view : Model -> Html Msg
view model =
    div []
        [ input [ placeholder "Napíš svoje meno", value model.name, onInput ChangeName ] []
        , button [ onClick Save ] [ text "Uložiť meno" ]
        , div [] [ text ("Aktuálne meno: " ++ model.name) ]
        ]
 

-- MAIN
main : Program () Model Msg
main =
    Browser.element
        { init = \() -> ( initialModel, Cmd.none )
        , view = view
        , update = update
        , subscriptions = subscriptions
        }