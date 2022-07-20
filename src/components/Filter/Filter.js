import { Card, Form } from "react-bootstrap"
import "./Filter.scss"
import { useState, useEffect, useContext } from "react"
import { FilterContext } from "../../FilterContext"

const Filter = ({ type, filter, data, setKeywordValue }) => {
  const [filtered, setFiltered] = useState("")

  useEffect(() => {
    let newContents = Object.entries(data)
    setFiltered(newContents)
  }, [data])

  const handleChange = (e) => {
    setKeywordValue(e.target.value.toLowerCase())
    console.log(data)
    // GRABS SEARCH BAR VALUE AND CONVERTS TO LOWERCASE, THEN PASSES TO APP.JS
  }
  return (
    <Card className="filterCard">
      <Form>
        <Card.Body>
          <Form.Label>
            <h5>Search {type} Containing:</h5>
          </Form.Label>
          <Form.Control
            type="text"
            placeholder="what are you looking for?"
            onChange={handleChange}
          />
        </Card.Body>
      </Form>
    </Card>
  )
}

export default Filter
