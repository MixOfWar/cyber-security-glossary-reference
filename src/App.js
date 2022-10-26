import { useState, useEffect } from 'react';
import { Container, Tab, Tabs } from 'react-bootstrap';
import { Header, ContentCard} from './components';
import { digitalForensics, ethicalHacking, networkDefense } from './data/index.js';
import './App.scss';

function App() {
	const [contents, setContents] = useState([]);
	const [term, setTerm] = useState(0);

	useEffect(() => {
		if (term === 1) {
			let newContents = Object.entries(ethicalHacking);
			setContents(newContents);
		} else if (term === 2) {
			let newContents = Object.entries(digitalForensics);
			setContents(newContents);
		} else {
			let newContents = Object.entries(networkDefense);
			setContents(newContents);
		}
	}, [term]);

	return (
		<Container className="App">
			<Header />

			<Tabs
				id='term-tabs'
				activeKey={term}
				onSelect={(e) => setTerm(e)}
				className='mb-3'
				justify
			>
				<Tab title="Network Defense Essentials" eventKey={0} >
					{networkDefense &&
						contents.map((name, index) => (
							<ContentCard
								name={name}
								key={index}
							/>
						))}
				</Tab>
				<Tab title="Ethical Hacking Essentials" eventKey={1}>
					{ethicalHacking &&
						contents.map((name, index) => (
							<ContentCard
								name={name}
								key={index}
							/>
						))}
				</Tab>
				<Tab title="Digital Forensics Essentials" eventKey={2}>
					{digitalForensics &&
						contents.map((name, index) => (
							<ContentCard
								name={name}
								key={index}
							/>
						))}
				</Tab>
			</Tabs>
		</Container>
	);
}

export default App;
