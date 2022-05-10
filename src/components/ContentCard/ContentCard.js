import { useState, useEffect } from 'react';
import { Card, ListGroup } from 'react-bootstrap';
import { SubContentCard } from '../index';
import './ContentCard.scss';

const ContentCard = ({ name, filterTerm, filterDefine }) => {
	const [terms, setTerms] = useState([]);
	const [show, setShow] = useState(false);

	const handleClick = (e) => {
		setShow(!show);
	};

	useEffect(() => {
		let newTerms = Object.entries(name[1]);
		setTerms(newTerms.sort());
		//eslint-disable-next-line
	}, []);

	return (
		<Card className={`contentCard ${name[0].toLowerCase()}`}>
			<Card.Header onClick={handleClick}>{name[0]}</Card.Header>
			{show && (
				<>
					<Card.Body>
						<ListGroup>
							{terms &&
								terms
									.filter((termName) =>
										termName[0].toLowerCase().includes(filterTerm.toLowerCase())
									)
									.filter((termDefinition) =>
										termDefinition[1]
											.toLowerCase()
											.includes(filterDefine.toLowerCase())
									)
									.map((definitions, index) => (
										<ListGroup.Item key={`sub${index}`}>
											<SubContentCard definitions={definitions} />
										</ListGroup.Item>
									))}
						</ListGroup>
					</Card.Body>
				</>
			)}
		</Card>
	);
};

export default ContentCard;
