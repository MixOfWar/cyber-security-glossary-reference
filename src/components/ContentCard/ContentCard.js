import { useState } from "react";
import { Card, ListGroup, Nav } from "react-bootstrap";
import { SubContentCard } from "../index";
import "./ContentCard.scss";

const ContentCard = ({ definition }) => {
  const [show, setShow] = useState(false);
  console.log(definition);

  const handleClick = (e) => {
    setShow(!show);
  };

  return (
    <Card
      className={`contentCard ${definition[0]
        .toLowerCase()
        .split(" ")
        .join("-")}`}
    >
      <Card.Header onClick={handleClick}>{definition[0]}</Card.Header>
      {show && (
        <>
          <Card.Subtitle>{definition[1].definition}</Card.Subtitle>
          <Card.Body>
            <ListGroup>
              {definition[1].types &&
                definition[1].types.map((type, index) => (
                  <ListGroup.Item key={index}>
                    <SubContentCard type={type} />
                  </ListGroup.Item>
                ))}
            </ListGroup>
          </Card.Body>
          <Card.Footer>
            {definition[1].mdnLink && (
              <>
                <Nav.Link href={`${definition[1].mdnLink}`}>
                  {" "}
                  Learn More
                </Nav.Link>
              </>
            )}
          </Card.Footer>
        </>
      )}
    </Card>
  );
};

export default ContentCard;
