import { useState, useEffect } from 'react';
import { Card } from 'react-bootstrap';

const SubContentCard = ({ definitions }) => {
  const [show, setShow] = useState(false);
  const [term, setTerm] = useState('')
  const [define, setDefine] = useState('')

	const handleClick = (e) => {
		setShow(!show);
  };
  
  useEffect(() => {
		let newTerm = definitions[0]
    setTerm(newTerm);
    
    let newDefine = definitions[1]
    setDefine(newDefine);
		//eslint-disable-next-line
	}, []);

	return (
		<Card className="innerCard">
			<Card.Title onClick={handleClick}>
				<h5>{term}</h5>
			</Card.Title>
			{show && (
				<>
					<Card.Body>{define}</Card.Body>
				</>
			)}
		</Card>
	);
};

export default SubContentCard;
