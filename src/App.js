import { useState, useEffect } from "react"
import { Container, CardGroup } from "react-bootstrap"
import { Header, ContentCard, Filter } from "./components"
import data from "./data"
import "./App.scss"

function App() {
  const [contents, setContents] = useState([])
  const [keywordValue, setKeywordValue] = useState("")
  useEffect(() => {
    let newContents = Object.entries(data)
    setContents(newContents)
  }, [])

  return (
    <Container className="App">
      <Header />
      <Filter data={data} setKeywordValue={setKeywordValue} />
      {/* {console.log(keywordValue)} */}
      <CardGroup>
        {data &&
          contents.map((name, index) => (
            <div>
              <ContentCard name={name} key={index} />
              {console.log(Object.values(name[1]).includes(keywordValue))}
              {/* {console.log(name[1])} */}
            </div>
          ))}
      </CardGroup>
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
