import { useState, useEffect, createContext } from "react"
import { Container, CardGroup } from "react-bootstrap"
import { Header, ContentCard, Filter } from "./components"
import { FilterContext, FilterProvider } from "./FilterContext"
import data from "./data"
import "./App.scss"

function App() {
  const [contents, setContents] = useState([])
  const [keywordValue, setKeywordValue] = useState("")

  useEffect(() => {
    let newContents = Object.entries(data)
    setContents(newContents)
  }, [])

  // CONTEXT FOR DATA, FILTERING WORD, FILTERING DEFINTION, COMBINING WORD AND DEFINTION INTO RESULTS,
  // AND SENDING RESULTS TO CONTENT CARD

  return (
    <Container className="App">
      <FilterContext.Provider>
        <Header />
        <Filter data={data} setKeywordValue={setKeywordValue} />
        <CardGroup>
          {data &&
            contents
              .filter((name) => {
                if (keywordValue === "") {
                  // CHECKS IF KEYWORD IS EMPTY
                  // console.log(name)
                  //NAME IS AN ARRAY WHERE INDEX 0 IS THE LETTER AND INDEX 1 IS THE OBJECT WITH WORD AND DEFINITIONS
                  return name
                } else if (name[0].toLowerCase().includes(keywordValue)) {
                  // CHECKS IF KEYWORD IS IN NAME

                  // console.log(name[0].toLowerCase().includes(keywordValue))
                  const arrayGrab = Object.keys(name[1])
                  // console.log(arrayGrab)
                  // GRABS THE WORDS, NO DEFINITIONS, AND IS SET IN ARRAY

                  console.log(Object.values(name[1]))
                  // LOGS THE DEFINITIONS BUT NO WORDS

                  const toLowerCase = arrayGrab.map((words) => {
                    return words.toLowerCase()
                  })
                  // CONVERTS THE WORDS TO LOWERCASE
                  console.log(arrayGrab[1] + " : " + Object.values(name)[1])
                  // LOGS THE WORDS (CAN GET ANY WORD BY INDEX VALUE) AND DEFINITIONS (GETS ALL DEFINITIONS AT ONCE)
                  // console.log(toLowerCase)
                  return toLowerCase
                }
              })
              .map((name, index) => (
                <>
                  {/* {console.log(keywordValue)} */}
                  <ContentCard name={name} key={index} />
                </>
              ))}
        </CardGroup>
      </FilterContext.Provider>
    </Container>
  )
}

// Index represents the numerical value of the letter of the alphabetic character
// For example, the letter A has an index of 0, the letter B has an index of 1, etc.

// Name is an array of two elements:
// [0] is the alphabetic character, [1] is the object containing the definitions
// For example, the name "A" has an array of two elements:
// ["A", {definition1: "definition1", definition2: "definition2"}]

export default App
