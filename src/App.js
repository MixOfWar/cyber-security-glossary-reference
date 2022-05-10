import { useState, useEffect } from 'react';
import { Container, CardGroup } from 'react-bootstrap';
import { Header, ContentCard, Filter } from './components';
import data from './data';
import './App.scss';

function App() {
	const [contents, setContents] = useState([]);

	useEffect(() => {
		let newContents = Object.entries(data);
		setContents(newContents);
	}, []);

	return (
		<Container className="App">
			<Header />
			
			<CardGroup>
				{data &&
					contents.map((name, index) => (
						<ContentCard
							name={name}
							key={index}
						/>
					))}
			</CardGroup>
		</Container>
	);
}

export default App;
