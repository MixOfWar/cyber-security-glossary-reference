import { useState } from "react";
import { Card, ListGroup, Nav } from "react-bootstrap";

const SubContentCard = ({ type }) => {
  const [show, setShow] = useState(false);
  console.log(type);

  const handleClick = (e) => {
    setShow(!show);
  };

  return (
    <Card className="innerCard">
      <Card.Title onClick={handleClick}>
        <h5>{type.name}</h5>{" "}
        {type.symbol ? <h5>{type.symbol}</h5> : <h5>{type.example}</h5>}
      </Card.Title>
      {show && (
        <>
          <Card.Body>
            {type.definition}
            {type.types ? (
              <>
                <ListGroup>
                  {type.types.map((type, index) => (
                    <ListGroup.Item>
                      <SubContentCard type={type} key={index} />
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              </>
            ) : null}
          </Card.Body>
          <Card.Footer>
            {type.mdnLink && (
              <>
                <Nav.Link href={`${type.mdnLink}`}>Learn More</Nav.Link>
              </>
            )}
          </Card.Footer>
        </>
      )}
    </Card>
  );
};

export default SubContentCard;
