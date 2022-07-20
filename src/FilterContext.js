import { useState, createContext, useEffect } from "react"
import { Header, ContentCard, Filter } from "./components"
import data from "./data"
export const FilterContext = createContext({})

export function FilterProvider({ children }) {
  const [dataSet, setDataSet] = useState(data)
  const [searchTerm, setSearchTerm] = useState("")
  const [searchTermDefinition, setSearchTermDefinition] = useState()
  const [combineSearchDefinition, setCombineSearchDefinition] = useState()
  const [results, setResults] = useState()

  const [contents, setContents] = useState([])

  useEffect(() => {
    let newContents = Object.entries(data)
    setContents(newContents)
  }, [])

  const handleChange = (e) => {
    setSearchTerm(e.target.value.toLowerCase())
    console.log(data)
    // GRABS SEARCH BAR VALUE AND CONVERTS TO LOWERCASE, THEN PASSES TO APP.JS
  }

  return (
    <FilterContext.Provider
      value={{
        dataSet,
        setDataSet,
        searchTerm,
        setSearchTerm,
        searchTermDefinition,
        setSearchTermDefinition,
        combineSearchDefinition,
        setCombineSearchDefinition,
        results,
        setResults,
        contents,
        setContents,
      }}
    >
      {children}
    </FilterContext.Provider>
  )
}
