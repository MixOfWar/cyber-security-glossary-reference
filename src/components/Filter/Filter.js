import { Card, Form } from "react-bootstrap"
import "./Filter.scss"
import { useState, useEffect } from "react"

const Filter = ({ type, filter, data, setKeywordValue }) => {
  console.log(data)
  const [filtered, setFiltered] = useState([])

  useEffect(() => {
    let newContents = Object.entries(data)
    console.log(newContents)
    setFiltered(newContents)
  }, [data])

  const handleChange = (e) => {
    setKeywordValue(e.target.value)
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
