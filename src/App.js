import { useState, useEffect } from 'react';
import { Container, Tab, Tabs } from 'react-bootstrap';
import { Header, ContentCard} from './components';
import { digitalForensics, ethicalHacking, networkDefense } from './data/index.js';
import './App.scss';

const initialState = {
	0: Object.entries(networkDefense),
	1: Object.entries(ethicalHacking),
	2: Object.entries(digitalForensics),
	term: 0,
}

function App() {
	const [data, setData] = useState(initialState);

	useEffect(() => {
		networkDefense && ethicalHacking && digitalForensics && setData({
			0: Object.entries(networkDefense),
			1: Object.entries(ethicalHacking),
			2: Object.entries(digitalForensics),
			term: 0
		})

	}, []);

	return (
		<Container className="App">
			<Header />

			<Tabs
				id='term-tabs'
				activeKey={data.term}
				onSelect={(key) => setData({...data, term: key})}
				className='mb-3'
				justify
			>
				<Tab title="Network Defense Essentials" eventKey={0} >
					{data[0] &&
						data[0].map((name, index) => (
							<ContentCard
								name={name}
								key={index}
							/>
						))}
				</Tab>
				<Tab title="Ethical Hacking Essentials" eventKey={1}>
					{data[1] &&
						data[1].map((name, index) => (
							<ContentCard
								name={name}
								key={index}
							/>
						))}
				</Tab>
				<Tab title="Digital Forensics Essentials" eventKey={2}>
					{data[2] &&
						data[2].map((name, index) => (
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
