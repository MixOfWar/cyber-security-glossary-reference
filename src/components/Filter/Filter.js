import { Card, Form } from 'react-bootstrap';
import './Filter.scss';

const Filter = ({ type, filter }) => {
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
						onChange={(e) => filter(e.target.value)}
					/>
				</Card.Body>
			</Form>
		</Card>
	);
};

export default Filter;
