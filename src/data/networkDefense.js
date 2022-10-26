const networkDefense = {
	A: {
		Availability:
			'Ensures information is available to authorized parties without any disruption.',
		Authentication:
			'Ensures the identity of an individual is verified by the system or service.',
		Authorization:
			'Authorization refers to the process of providing permission to access the resources or perform an action on the network.',
		Accounting:
			'Accounting is a method of keeping track of user actions on the network. It keeps track of who, when, and how the users access the network.',
		'Application Level Gateways':
			'Application level gateways can filter packets at the application layer of the OSI model.',
		'Application Proxy':
			'An application-level proxy works as a proxy server and filters connections for specific services.',
		'Anonymous Proxy':
			'An anonymous proxy does not transfer information about the IP address of its user, thereby hiding information about the user and their surfing interests.',
		'Anomaly Detection':
			'It detects the intrusion based on the fixed behavioral characteristics of the users and components in a computer system.',
		'Administrative Security Controls':
			'Administrative security controls are management limitations, operational and accountability procedures, and other controls that ensure the security of an organization.',
		'Access Control':
			'Access control is the selective restriction of access to an asset or a system/network resource.',
		Alert:
			'An alert is a graduated event that notifies that a particular event (or series of events) has reached a specified threshold and needs appropriate action by a responsible party.',
		'Alert Systems':
			'An alert system sends an alert message when any anomaly or misuse is detected.',
		'Alarm System':
			'Alarms are used to draw attention when there is a breach or during an attempt of breach.',
		'Access point (AP)':
			'Used to connect wireless devices to a wireless/wired network.',
		'Anomaly-based Detection':
			'The anomaly-based detection process depends on observing and comparing the observed events with the normal behavior and then detecting any deviation from it.',
		'AAA Server':
			'The AAA server is used to establish secure access in a remote-access VPN environment.',
		'Anything-as-a-Service (XaaS)':
			'Anything as a service (XaaS) is a cloud-computing and remote-access service that offers anything as a service over the Internet based on the user’s demand.',
		Association:
			'It refers to the process of connecting a wireless device to an AP.',
		Antenna: 'Converts electrical impulses into radio waves and vice versa.',
		'Asymmetric Encryption':
			'Asymmetric encryption uses two separate keys to carry out encryption and decryption.',
		'Advanced Encryption Standard (AES)':
			'The AES is a National Institute of Standards and Technology (NIST) specification for the encryption of electronic data.',
		'Audit Trails':
			'An audit trail is a set of records that provide documentary evidence of a system’s activity.',
		'Application Containers':
			'These are containers used to run a single service. They have layered file systems and are built on top of OS container technologies.',
		ANT: 'It is a wireless sensor protocol that enables communication between sensors and their controllers.',
	},
	B: {
		'Biometric Authentication':
			'Biometrics is a technology which identifies human characteristics for authenticating people.',
		Bollards:
			'A bollard may be defined as a short vertical post which controls and restricts motor vehicles to the parking areas, offices etc.',
		'Bastion Host':
			'A bastion host is a computer system designed and configured to protect network resources from attacks.',
		Bandwidth:
			'It describes the amount of information that may be broadcast over a connection.',
		'Basic Service Set Identifier (BSSID)':
			'It is the media access control (MAC) address of an access point (AP) or base station that has set up a basic service set (BSS).',
		'Behavior-based IDS':
			'Behavior-based intrusion detection techniques assume an intrusion can be detected by observing a deviation from normal or expected behavior of the system or users.',
		Bluetooth:
			'In the Bluetooth technology, data is transmitted between cell phones, computers, and other networking devices over short distances.',
		Biometrics:
			'Biometrics is an advanced and unique security technology that utilizes an individual’s physical attributes such as fingerprint, iris, face, voice, and behavior for verifying their identity.',
		'Bring Your Own Device (BYOD)':
			'BYOD refers to a policy that allows employees to bring their devices such as laptops, smartphones, and tablets to the workplace. Business Critical Data: Business critical data contains information that is important for business operation.',
	},
	C: {
		Confidentiality:
			'Ensures information is not disclosed to unauthorized parties',
		'Compensating Controls':
			'These controls are used as an alternative control when the intended controls fail or cannot be used.',
		'Combination Locks':
			'It has a combination of numbers and letters. The user needs to provide the combination to open the lock.',
		'Computer Fraud and Abuse Act':
			'States that, whoever intentionally accesses a computer without authorization or exceeds authorized access, and thereby obtains information from any protected computer, and if the conduct involves an interstate or foreign communication, shall be punished under the Act.',
		'Circuit-Level Gateway':
			'Circuit level gateways work at the session layer of the OSI model, or the TCP layer of TCP/IP.',
		'Client-to-Site (Remote-access) VPNs':
			'Remote-Access VPNs allow individual hosts or clients, such as telecommuters and mobile users to establish secure connections to a company’s network over the Internet.',
		Container:
			'Containers refer to virtualization based on an operating system, in which the kernel’s operating system functionality is replicated on multiple instances of isolated user space.',
		'Cloud Computing':
			'Cloud computing is an on-demand delivery of IT capabilities where IT infrastructure and applications are provided to subscribers as a metered service over a network.',
		'Cloud Storage':
			'Cloud storage is a data storage medium used to store digital data in logical pools using a network.',
		'Cloud-to-Cloud (Back-End Data-Sharing) Communication Model':
			'This type of communication model extends the device-to-cloud communication type such that the data from the IoT devices can be accessed by authorized third parties.',
		'Cloud Platform':
			'In an IoT ecosystem, the cloud component is referred to as the central aggregation and data management point.',
		'Cloud Data Backup':
			'Storing backup data on storage provided by an online backup provider.',
		'Container-as-a-Service (CaaS)':
			'This cloud computing model provides containers and clusters as a service to its subscribers.',
		'Community Cloud':
			'Shared infrastructure between several organizations from a specific community with common concerns (security, compliance, jurisdiction, etc.).',
		'Cloud Consumer':
			'A person or organization that uses cloud computing services.',
		'Cloud Provider':
			'A person or organization providing services to interested parties via network access.',
		'Cloud Carrier':
			'A cloud carrier acts as an intermediary that provides connectivity and transport services between CSPs and cloud consumers.',
		'Cloud Auditor':
			'A cloud auditor is a party that performs an independent examination of cloud service controls to express an opinion thereon.',
		'Cloud Broker':
			'An entity that manages cloud services in terms of use, performance, and delivery, and maintains the relationship between cloud providers and consumers.',
		'Cellular Communication':
			'Cellular communication is based on a single network tower that serves devices located within a specific radius.',
		'Cross-Container Attacks':
			'Gaining access to a container and utilizing it to attack other containers of the same host or within the local network.',
		'Communication Layer':
			'The communication (connectivity/edge computing) layer includes the components of communication protocols and networks used for connectivity and edge computing.',
		'Cloud Layer':
			'Servers hosted in the cloud accept, store, and process the sensor data received from IoT gateways.',
		Contraband:
			'Contraband includes materials that are banned from entering the environment such as explosives, bombs, weapons, etc.',
		'5G Cellular (Mobile) Communication':
			'It is a broadband cellular network that operates at high bandwidth with low latency and provides high-speed data downloads.',
		'Centralized IDS':
			'In a centralized system, the data is gathered from different sites to a central site.',
		'Context-aware Authentication':
			'Context-aware authentication is a type of enhanced security technique that uses the contextual information of a user for enhancing data security decisions.',
		Containerization:
			'Containerization is a technique in which all personal and organizational data are segregated on an employee’s mobile device.',
		'Choose Your Own Device (CYOD)':
			'CYOD refers to a policy in the employees select their device of choice from a pre-approved set of devices (laptops, smartphones, and tablets) to access company data according to the access privileges of an organization.',
		'Corporate Owned, Personally Enabled (COPE)':
			'Corporate Owned, Personally Enabled (COPE) refers to a policy that allows employees to use and manage the devices purchased by the organizations.',
		'Company Owned, Business Only (COBO)':
			'Company Owned, Business Only (COBO) refers to a policy that allows employees to use and manage the devices purchased by the organization but restrict the use of the device for business use only.',
		Cryptography:
			'Cryptography is the practice of concealing information by converting plaintext (readable format) into cipher text (unreadable format) using a key or encryption scheme.',
		CCMP: 'An encryption protocol used in WPA2 for stronger encryption and authentication.',
		'Certification Authorities':
			'Certification authorities (CAs) are trusted entities that issue digital certificates.',
		'Centralized Authorization':
			'It maintains a single database for authorizing all the network resources or applications.',
		'Command Console':
			'It provides a user interface to an administrator for the purpose of receiving and analyzing security events, alert message, and log files.',
		Ciphers:
			'A cipher is an algorithm for performing encryption and decryption.',
	},
	D: {
		'Deterrence Controls':
			'These are used to discourage the violation of security policies.',
		'Detection Controls':
			'These are used to detect unauthorized access attempts.',
		'Discretionary Access Control (DAC)':
			'DAC determines the access control taken by any possessor of an object in order to decide the access control of a subject on that object.',
		'Detective Controls':
			'These controls detect security violations and record any intrusion attempts.',
		'Digital Locks':
			'Digital locks use fingerprint, smart card or a PIN on the keypad to unlock.',
		'Demilitarized Zone (DMZ)':
			'A computer subnetwork is placed between the organization’s private network such as a LAN, and an outside public network such as the Internet, and acts as an additional security layer.',
		'Dual Firewall DMZ':
			'The dual firewall approach uses two firewalls to create a DMZ.',
		'Distributed IDS':
			'A distributed intrusion detection system (dIDS) consists of multiple IDSs over a large network.',
		'Database Honeypots':
			'Database honeypots employ fake databases that are vulnerable to perform database-related attacks such as SQL injection and database enumeration.',
		Docker:
			'Docker is an open source technology used for developing, packaging, and running applications and all its dependencies in the form of containers, to ensure that the application works in a seamless environment.',
		'Docker Networking':
			'The Docker networking architecture is developed on a set of interfaces known as container network model (CNM). CNM provides application portability across heterogeneous infrastructures.',
		'Docker Registry Attacks': 'Gaining access to the docker registry.',
		'Device Layer':
			'The device or thing layer of IoT includes the hardware that constitutes IoT devices.',
		'Device-to-Device Communication':
			'In this type of communication, inter-connected devices interact with each other through the Internet, but they predominantly use protocols such as ZigBee, Z-Wave or Bluetooth.',
		'Device-to-Cloud Communication':
			'In this type of communication, devices communicate with the cloud directly, rather than directly communicating with the client to send or receive data or commands.',
		'Device-to-Gateway Communication':
			'In the device-to-gateway communication model, the IoT device communicates with an intermediate device called a gateway, which in turn communicates with the cloud service.',
		'Decentralized Authorization':
			'A decentralized authorization maintains a separate database for each resource.',
		'Data Backup Strategy':
			'An ideal backup strategy includes steps ranging from selecting the right data to conducting a test data restoration drill.',
		'Direct-sequence Spread Spectrum (DSSS)':
			'DSSS is a spread spectrum technique that multiplies the original data signal with a pseudo-random noise-spreading code.',
		'Directional Antenna':
			'A directional antenna can broadcast and receive radio waves from a single direction.',
		'Dipole Antenna':
			'A dipole antenna is a straight electrical conductor measuring half a wavelength from end to end, and it is connected at the center of the radio frequency (RF) feed line.',
		'Data Encryption Standard (DES)':
			'DES is designed to encipher and decipher blocks of data consisting of 64 bits under control of a 56-bit key.',
		'Digital Signature Algorithm (DSA)':
			'The digital signature algorithm (DSA) is a Federal Information Processing Standard (FIPS) for digital signatures.',
		'Digital Signature':
			'Digital signatures use the asymmetric key algorithms to provide data integrity.',
		'Digital Certificates':
			'Digital certificates allow a secure exchange of information between a sender and a receiver.',
		'Data Security':
			'Data security involves the application of various data security controls to prevent any intentional or unintentional act of data misuse, data destruction, and data modification.',
		'Data Protection Act 2018 (DPA)':
			'The DPA is an act to make provision for the regulation of the processing of information relating to individuals.',
		'Data Access Control':
			'Data access controls enable authentication and authorization of users to access the data.',
		'Data Encryption':
			'Protecting information by transforming it so that it becomes unreadable for an unauthorized party.',
		'Data Masking':
			'Protecting information by obscuring specific areas of data with random characters or codes.',
		'Data Resilience and Backup':
			'Making a duplicate copy of critical data to be used for restoring and recovery purposes.',
		'Data Destruction':
			'It involves destroying the data so that it cannot be recovered and used for a wrong motive.',
		'Data Retention':
			'Storing data securely for compliance or business requirements.',
		'Disk Encryption':
			'Encryption of data stored in a physical or logical disk.',
		'Data Backup':
			'Data backup is the process of making a duplicate copy of critical data, such as physical (paper) and computer records.',
		'Differential Data Backup':
			'All data that has been changed since the last full backup is copied to the backup media.',
		'Data Loss Prevention (DLP)':
			'DLP includes a set of software products and processes that do not allow users to send confidential corporate data outside the organization.',
		'Denial of Service Traffic Signatures':
			'Traffic containing certain signatures that indicate a DoS attempt that floods a server with a large number of requests.',
	},
	E: {
		'Enterprise Information Security Policy (EISP)':
			'EISP drives an organization’s scope and provides direction to their security policies.',
		'Electric/Electromagnetic Locks':
			'Electric locks or an electronic locking system operates on an electric current.',
		'Electromagnetic Interference (EMI)':
			'EMI occurs when electronic device’s performance is interrupted or degraded due to electromagnetic radiation or conduction.',
		'Email Honeypots':
			'Email honeypots are also called email traps. They are nothing but fake email addresses that are specifically used to attract fake and malicious emails from adversaries.',
		Encapsulation:
			'Encapsulation is the method in which protocols have separate functions to communicate among each other by hiding the data.',
		Endpoint:
			'This connects a sandbox to a network and abstracts the actual connection to the network from the application.',
		'Enterprise Mobility Management (EMM)':
			'EMM consists of tools and technologies used in an organization to secure the data in employees’ personal (BYOD) and organizational devices.',
		EDGE: 'The edge is the main physical device in the IoT ecosystem that interacts with its surroundings and contains various components like sensors, actuators, operating systems, hardware and network, and communication capabilities.',
		Encryption:
			'Encryption is the practice of concealing information by converting a plain text (readable format) into a cipher text (unreadable format) using a key or an encryption scheme.',
		'Explicit Authorization':
			'An explicit authorization maintains separate authorization details for each resource request.',
		EAP: 'The Extensible Authentication Protocol (EAP) supports multiple authentication methods, such as token cards, Kerberos, and certificates.',
	},
	F: {
		Firewall:
			'Firewall is a software or hardware, or a combination of both, which is generally used to separate a protected network from an unprotected public network.',
		'Freedom of Information Act (FOIA)':
			'The Freedom of Information Act (FOIA) has provided the public the right to request access to records from any federal agency.',
		'False Positive (No attack – Alert)':
			'A false positive occurs if an event triggers an alarm when no actual attack is in progress.',
		'False Negative (Attack – No Alert)':
			'A false negative is a condition that occurs when an IDS fails to react to an actual attack event.',
		'Function-as-a-Service (FaaS)':
			'This cloud computing service provides a platform for developing, running, and managing application functionalities without the complexity of building and maintaining necessary infrastructure.',
		'Frequency-Hopping Spread Spectrum (FHSS)':
			'FHSS, also known as frequency-hopping code-division multiple access (FH-CDMA), is a method of transmitting radio signals by rapidly switching a carrier among many frequency channels.',
		'Fingerprint Scanning':
			'Compares two fingerprints for verification and identification on the basis of the patterns on the finger.',
		'Face Recognition':
			'Compares and identifies a person on the basis of the facial features from an image or a video source.',
		'Fences/Electric fences/Metal Rails':
			'Fences/metal rails/electric fences generally mark the restricted areas, controlled areas and prevents unauthorized access.',
		'Full Mesh VPN Topology':
			'In a fully meshed VPN network, all peers can communicate with each other, making it a complex network.',
		'Full Virtualization':
			'In this type of virtualization, the guest OS is not aware that it is running in a virtualized environment.',
		'File System Virtualization':
			'This refers to the virtualization of data at the level of the file system.',
		'Fabric Virtualization':
			'This level of virtualization makes the virtual devices independent of the physical computer hardware.',
		'Full Data Backup':
			'This is also called a normal backup. It copies all files and compresses them to save space.',
		'File-Level Encryption': 'Encryption of data stored in files/folders.',
		'Full Device Encryption':
			'Full disk encryption is a security feature that can encrypt all the information stored on any storage medium within a mobile device.',
	},
	G: {
		'Gramm-Leach-Bliley Act (GLBA)':
			'The Gramm-Leach-Bliley Act (GLB Act or GLBA) is a United States federal law that requires financial institutions to explain how they share and protect their customers’ private information.',
		'General Data Protection Regulation (GDPR)':
			'The GDPR will levy harsh fines against those who violate its privacy and security standards, with penalties reaching tens of millions of euros.',
		'Guest Machine':
			'Independent instance of an operating system created by virtual machine monitor.',
		'Global System for Mobile Communications (GSM)':
			'It is a universal system used for mobile data transmission in wireless networks worldwide.',
		'Global Positioning System (GPS)':
			'GPS is a radio navigation and positioning system based on satellite communication.',
		Geolocation:
			'Geolocation is a technology that can identify the real-world geographical location of users or devices when connected to the Internet.',
		Geofencing:
			'Geofencing is a technique through which mobile-application marketers utilize the location of the user to gather information.',
		'Government Access to Keys (GAK)':
			'GAK refers to the statutory obligation of individuals and organizations to disclose their cryptographic keys to government agencies.',
	},
	H: {
		'Hypertext Transfer Protocol Secure (HTTPS)':
			'HTTPS ensures secure communication between two computers over HTTP.',
		'Health Insurance Portability and Accountability Act (HIPAA)':
			'The HIPAA Privacy Rule provides federal protections for the individually identifiable health information held by covered entities and their business associates and gives patients an array of rights to that information.',
		'Hardware Firewalls':
			'A hardware firewall is either a dedicated stand-alone hardware device or it comes as part of a router.',
		'Host-based Firewalls':
			'The host-based firewall is used to filter inbound/outbound traffic of an individual computer on which it is installed.',
		Honeypot:
			'A honeypot is an information system resource that is expressly set up to attract and trap people who attempt to penetrate an organization’s network.',
		Honeynets:
			'Honeynets are networks of honeypots. They are very effective in determining the entire capabilities of the adversaries.',
		'Hardware VPNs':
			'A dedicated hardware VPN appliance is used to connect routers and gateways to ensure communication over an insecure channel.',
		Hypervisor:
			'An application or firmware that enables multiple guest operating systems to share a host’s hardware resources.',
		'Host Machine':
			'Real physical machine that provides computing resources to support virtual machines.',
		'Hybrid Cloud':
			'Combination of two or more clouds (private, community, or public) that remain unique entities but are bound together, thereby offering the benefits of multiple deployment models.',
		Hotspot:
			'These are places where wireless networks are available for public use.',
		'Host Intrusion Detection Systems (HIDS)':
			'HIDS is installed on a specific host and is used to monitor, detect, and analyze events occurring on that host.',
		'Hybrid Intrusion Detection Systems (Hybrid IDS)':
			'A hybrid IDS is a combination of both HIDS and NIDS.',
		'High-Interaction Honeypots':
			'High-interaction honeypots do not emulate anything; they run actual vulnerable services or software on production systems with real OS and applications',
		'Hybrid VPNs':
			'Hybrid VPNs are those with trusted VPNs as part of the secure VPNs. They implement different network components of an organization at the same time in order to confirm security at very low costs.',
		'Hub-and-Spoke VPN Topology':
			'In hub-and-spoke technology, the main organization is considered the hub, and its remote offices are considered the spokes.',
		'Hybrid Virtualization':
			'In this type of virtualization, the guest OS adopts the functionality of para virtualization and uses the VMM for binary translation to different types of hardware resources.',
		'Hot Backup (Online)':
			'It is also called as dynamic backup or active backup. In a hot backup, the system continues to perform the backup even when the user is accessing the system.',
		'Hash-based Message Authentication Code (HMAC)':
			'HMAC is a type of message authentication code (MAC) that uses a cryptographic key along with a cryptographic hash function.',
	},
	I: {
		Integrity:
			'Ensures information is not modified or tampered with by unauthorized parties.',
		'Internet Protocol Security (IPsec)':
			'IPsec is a network layer protocol that ensures a secure IP level communication.',
		'Identity and Access Management (IAM)':
			'Identity and access management (IAM) is responsible for providing the right individual with the right access at the right time.',
		'Issue Specific Security Policy (ISSP)':
			'ISSP directs the audience on the usage of technology-based systems with the help of guidelines.',
		'Intrusion Detection and Prevention System (IDS/IPS)':
			'An intrusion detection and prevention system (IDS/IPS) is a network security appliance that inspects all inbound and outbound network traffic for suspicious patterns that might indicate a network or system security breach.',
		'Iris Scanning':
			'Analyzes the colored part of the eye suspended behind the cornea.',
		'Implicit Authorization':
			'Implicit authorization provides access to the resources indirectly.',
		'Internal Bastion Host':
			'It can be single-homed or multi-homed bastion hosts.',
		'Interval-based IDS':
			'Interval-based or offline analysis refers to the storage of the intrusion-related information for further analysis.',
		'IPsec Server':
			'The IPsec server enhances VPN security through the use of strong encryption algorithms and authentication.',
		'Infrastructure-as-a-Service (IaaS)':
			'Provides virtual machines and other abstracted hardware and operating systems which may be controlled through a service API.',
		'Identity-as-a-Service (IdaaS)':
			'This cloud computing service offers authentication services to the subscribed enterprises and is managed by a third-party vendor to provide identity and access management services.',
		'Information Assurance (IA) Principles':
			'Information assurance (IA) principles act as enablers for an organization’s security activities to protect and defend its network from security attacks.',
		'ISM band':
			'A set of frequencies for the international industrial, scientific, and medical communities.',
		'Industrial, Scientific, and Medical (ISM) band':
			'This band is a set of frequencies used by the international industrial, scientific, and medical communities.',
		'Infrared (IR)':
			'IR is a wireless technology for transferring data between two devices in the digital form within a short range of up to 5 m.',
		'Internet of Things (IoT)':
			'IoT also known as the Internet of Everything (IoE), refers to computing devices that are web-enabled and have the capability of sensing, collecting, and sending data using sensors, and the communication hardware and processors.',
		'Infrastructure Network Topology':
			'Devices in the wireless network are connected through an AP.',
		'IoT User Management':
			'Provide control over the users who have access to an IoT system.',
		'IoT Device Management':
			'IoT device management helps security professionals to track, monitor, and manage physical IoT devices from a remote location.',
		'Incremental Data Backup':
			'Only files that have been changed or created after the last backup are copied to the backup media.',
		IDE: 'Integrated drive electronics (IDE) allows the connection of two devices per channel. It is normally used for internal devices as the cables are large and flat.',
		'Informational Traffic Signature':
			'Traffic containing certain signatures that may appear suspicious but might not be malicious.',
	},
	J: {},
	K: {
		Kerberos:
			'Kerberos is a network authentication protocol that is implemented for authenticating requests in computer networks.',
		Kubernetes:
			'Kubernetes, also known as K8s, is an open-source, portable, extensible, orchestration platform developed by Google for managing containerized applications and micro services.',
	},
	L: {
		'Lighting System':
			'Adequate lighting should be provided inside, outside, and at the entrance of the building which helps in seeing long distances during security patrols.',
		'Logical Segmentation':
			'Logical segmentation utilizes VLANs, which are isolated logically without considering the physical locations of devices.',
		LEAP: 'Lightweight EAP (LEAP) is a proprietary version of EAP developed by Cisco.',
		'Low-interaction Honeypots':
			'Low-interaction honeypots emulate only a limited number of services and applications of a target system or network.',
	},
	M: {
		'Mandatory Access Control (MAC)':
			'The MAC determines the usage and access policies for the users.',
		'Mechanical Locks':
			'Provide an easy method to restrict unauthorized access in an organization.',
		Mantrap:
			'It is a security system having an entry and exit door on opposite sides, separating non-secure area from secure area.',
		'Malware Honeypots':
			'Malware honeypots are used to trap malware campaigns or malware attempts over the network infrastructure.',
		'Medium-interaction Honeypots':
			'Medium-interaction honeypots simulate a real OS as well as applications and services of a target network.',
		'Management Server':
			'Virtualization platform components used to directly manage the virtual machines and to simplify the administration of resources.',
		'Multi-layer Security':
			'Involves preventing unauthorized access to IoT things by using multi-factor authentication (MFA), Transport Layer Security (TLS), device identity management, etc.',
		'Multiport Memory Controller':
			'An MPMC provides access to memory for up to eight ports. A memory controller can be present as a separate chip or as an integrated memory.',
		'Multi Cloud':
			'It is a dynamic heterogeneous environment that combines workloads across multiple cloud vendors that are managed via one proprietary interface to achieve long-term business goals.',
		'Management Console':
			'Interface used to access, configure, and manage the virtualization product.',
		'Multi-homed Bastion Host':
			'A firewall device with at least two network interfaces.',
		'Multiple Input, Multiple output Orthogonal Frequency-division Multiplexing (MIMO-OFDM)':
			'An air interface for 4G and 5G broadband wireless communications.',
		'Mobile Device Management (MDM)':
			'MDM provides platforms for over-the-air or wired distribution of applications, data, and configuration settings for all types of mobile devices, including mobile phones, smartphones, and tablet computers.',
		'Mobile Application Management (MAM)':
			'Mobile application management (MAM) is a software or service that enables network defenders to secure, manage, and distribute enterprise applications on employee mobile devices.',
		'Mobile Content Management (MCM)':
			'Mobile content management (MCM) or mobile information management (MIM) solutions provide secure access to corporate data on smartphones, tablets, and other mobile devices.',
		'Mobile Email Management (MEM)':
			'Mobile email management (MEM) solutions ensures the security of the corporate email infrastructure and data.',
		'Mobile Security Management':
			'Mobile security management involves actions and precautionary steps for securing the organizational data and mobile devices used by employees.',
		MD5: 'The MD5 algorithm takes a message of arbitrary length as the input and then outputs a 128-bit fingerprint or message digest of the input.',
		MD6: 'MD6 uses a Merkle-tree-like structure to allow for large-scale parallel computation of hashes for very long inputs.',
	},
	N: {
		'Non-Repudiation':
			'Ensures that a party in a communication cannot deny sending the message.',
		'Network Segmentation':
			'Network segmentation is the practice of splitting a network into smaller network segments and separating groups of systems or applications from each other.',
		'Network Defense Essentials (NDE)':
			'Network Defense Essentials (NDE) is a security program covering the fundamental concepts of network security.',
		'Network Virtualization':
			'Network virtualization is a process of combining all the available network resources and enabling security professionals to share these resources amongst the network users using a single administrative unit.',
		'Network Security Controls':
			'Network security controls are the security features that should be appropriately configured and implemented to ensure network security.',
		'Network Security Protocols':
			'Network security protocols implement security related operations to ensure the security and integrity of data in transit.',
		'Network Security Devices':
			'Network security appliances are devices that are deployed to protect computer networks from unwanted traffic and threats.',
		'Network Intrusion Detection System (NIDS)':
			'NIDS is used to observe the traffic for any specific segment or device and recognize the occurrence of any suspicious activity in the network and application protocols.',
		'Network Packets':
			'A network packet is a unit of data transmitted over a network for communication.',
		'Network Access Server (NAS)':
			'It is also called a media gateway or a remote-access server (RAS). It is responsible for setting up and maintaining each tunnel in a remote-access VPN.',
		Network:
			'A network is a collection of endpoints that have connectivity between them.',
		'Network Drivers':
			'These are pluggable and provide the actual implementation for the functioning of the network.',
		'Network Defense':
			'The ultimate goal of network defense is to protect an organization’s information, systems, and network infrastructure from unauthorized access, misuse, modification, service denial, or any degradation and disruptions.',
		'Network Access Controls':
			'Network access controls offer various access control mechanisms for network devices like routers and switches.',
		'Non-routing Dual-homed Hosts':
			'This type of the host is completely a firewall, or it might be a component of a multi-faceted firewall.',
		'Network-based Firewalls':
			'The network-based firewall is used to filter inbound/outbound traffic from Internal LAN.',
		'Network Address Translation (NAT)':
			'Network address translation separates IP addresses into two sets and enables the LAN to use these addresses for internal and external traffic, respectively.',
		'Next Generation Firewall (NGFW)':
			'NGFW firewall technology is third-generation firewall technology that moves beyond port/protocol inspection.',
		nvSRAM:
			'nvSRAM is the fastest nonvolatile RAM in the industry with 20 ns read and write access time.',
		'NAND Flash Memory':
			'Provides a non-volatile storage for the RAID system’s primary cache.',
		'Network Sensors':
			'Network sensors are hardware and software components that monitor network traffic and trigger alarms if any abnormal activity is detected.',
		'Non-transparent Proxy':
			'Non-transparent proxies are also known as explicit proxies and require client software to be configured to use the proxy server.',
		'Near-field Communication (NFC)':
			'NFC covers very short distances. It employs electromagnetic induction to enable communication between devices connected within 10 cm.',
		'Network Attached Storage (NAS)':
			'NAS is a file-based data storage service and a dedicated computer appliance shared over the network.',
		'Network Traffic Monitoring':
			'Network monitoring is a retrospective security approach that involves monitoring a network for abnormal activities, performance issues, bandwidth issues, etc.',
		'Network Traffic Signatures':
			'A signature is a set of traffic characteristics such as a source/destination IP address, ports, Transmission Control Protocol (TCP) flags, packet length, time to live (TTL), and protocols. Signatures are used to define the type of activity on a network.',
		'Normal Traffic Signatures':
			'Acceptable traffic patterns allowed to enter the network.',
	},
	O: {
		Object:
			'An object is an explicit resource on which an access restriction is imposed.',
		Operation: 'An operation is an action performed by a subject on an object.',
		'OS Containers':
			'OS containers are virtual environments sharing the kernel of the host environment that provides them isolated user space.',
		'Orthogonal Frequency-Division Multiplexing (OFDM)':
			'Method of encoding digital data on multiple carrier frequencies.',
		'Omnidirectional Antenna':
			'Omnidirectional antennas radiate electromagnetic (EM) energy in all directions.',
		'Onsite Data Backup': 'Storing backup data at onsite data storage only.',
		'Offsite Data Backup':
			'Storing backup data in remote locations in fire-proof, indestructible safes.',
		'Open System Authentication':
			'Open system authentication is a null authentication algorithm that does not verify whether it is a user or a machine requesting network access.',
		'OS Assisted Virtualization or Para Virtualization':
			'In this type of virtualization, the guest OS is aware of the virtual environment in which it is running and communicates with the host machine to request for resources.',
		'Operating System Virtualization':
			'This type of virtualization enables the hardware to execute multiple operating systems simultaneously.',
	},
	P: {
		'Preventive Approach':
			'Consist of methods or techniques that are used to avoid threats or attacks on the target network.',
		'Proactive Approaches':
			'Consist of methods or techniques that are used to make informed decisions on potential attacks in the future on the target network.',
		'Prevention Controls':
			'These are used to prevent unwanted or unauthorized access to resources.',
		'Principle of Least Privilege (POLP)':
			'The principle of least privilege (POLP) extends the need-to-know principle in providing access to a system.',
		'Password Authentication':
			'Password Authentication uses a combination of a username and a password to authenticate the network users.',
		Policies:
			'Policies are high-level statements dealing with the administrative network security of an organization.',
		'Promiscuous Policy':
			'This policy does not impose any restrictions on the usage of system resources.',
		'Permissive Policy':
			'This policy is wide open, and only known dangerous services/attacks or behaviors are blocked.',
		'Paranoid Policy':
			'A paranoid policy forbids everything. There is a strict restriction on all company computers, whether it is system or network usage.',
		'Prudent Policy':
			'A prudent policy starts with all services blocked. The Network defender enables safe and necessary services individually.',
		'Password Blacklist':
			'A password blacklist contains a list of words that are prohibited from use as passwords because of their familiarity.',
		'Physical Security':
			'It deals with restricting unauthorized physical access to the infrastructure, office premises, workstations, and employees of the organization.',
		'Physical Security Policy':
			'Physical security policy defines guidelines to ensure that adequate physical security measures are in place.',
		'Payment Card Industry Data Security Standard (PCI-DSS)':
			'PCI-DSS is a proprietary information security standard for organizations that handle cardholder information for major debit, credit, prepaid, e-purse, ATM, and POS cards.',
		'Password Policy':
			'Password policy provides guidelines for using strong passwords for an organization’s resources.',
		'Preventive Controls':
			'These controls prevent security violations and enforce various access control mechanisms.',
		'Physical Barriers':
			'Physical barriers restrict unauthorized people from entering the building; always use a combination of barriers to deter unauthorized entry.',
		'Physical Segmentation':
			'Physical segmentation is a process of splitting a larger network into smaller physical components.',
		'Packet Filtering Firewall':
			'Packet filtering firewalls work at the network level of the OSI model (or the IP layer of TCP/IP).',
		'Protocol Anomaly Detection':
			'Protocol anomaly detection depends on the anomalies specific to a protocol.',
		'Production Honeypots':
			'Production honeypots are deployed inside the production network of the organization along with other production servers.',
		'Proxy Servers':
			'A proxy server is an application that can serve as an intermediary when connecting with other computers.',
		'Platform-as-a-Service (PaaS)':
			'This cloud computing service offers development tools, configuration management, and deployment platforms on-demand that can be used by subscribers to develop custom applications.',
		'Public Cloud':
			'The provider makes services such as applications, servers, and data storage available to the public over the Internet.',
		'Private Cloud':
			'A private cloud is a cloud infrastructure operated by a single organization and implemented within a corporate firewall.',
		'Parabolic Grid Antenna':
			'A parabolic grid antenna uses the same principle as a satellite dish, but it does not have a solid dish. It consists of a semi-dish in the form of a grid consisting of aluminum wires.',
		PEAP: 'It is a protocol that encapsulates the EAP within an encrypted and authenticated Transport Layer Security (TLS) tunnel.',
		'Point-to-point (P2P) Connection':
			'A P2P connection enables secure communication between two mobile devices without data encryption.',
		'Pure Honeypots':
			'Pure honeypots emulate the real production network of a target organization.',
		'Packet Filters':
			'Packet filters examine the routing information of the packet.',
		'Point-to-Point VPN Topology':
			'In a point-to-point topology, any two endpoints are considered as peer devices which can communicate with each other. Any of the devices can be used to initiate the connection.',
		'Process Layer':
			'The process layer gathers information and processes the received information.',
		'Point-to-multipoint Connection':
			'A point-to-multipoint (P2MP, PTMP, and PMP) connection allows one-to-many connections by providing multiple paths from a single location to several other locations.',
		'Passwords and PINs':
			'Passwords and PINs are basic security features used in all mobile devices.',
		'Push Notification Services':
			'It is a messaging feature that originates from a server and enables the delivery of data or a message from an application to a mobile device without any explicit request from the user.',
		'Public Key Infrastructure (PKI)':
			'A public key infrastructure (PKI) is a security architecture developed for increasing the confidentiality of the information exchanged over the Internet.',
		'Physical Security Controls':
			'Physical security controls provide physical protection of the information, buildings, and all other physical assets of an organization.',
		'Pretty Good Privacy (PGP)':
			'Pretty good privacy (PGP) is an application layer protocol which provides cryptographic privacy and authentication for network communication.',
		'Primary RAID Memory Cache':
			'Cache is used to write the data in transition. A RAID system uses a cache to speed up I/O performance on the storage system.',
	},
	Q: {},
	R: {
		'Reactive Approach':
			'Consist of methods or techniques that are used to detect attacks on the target network.',
		'Retrospective Approaches':
			'Consist of methods or techniques that examine the causes for attacks, and contain, remediate, eradicate, and recover from damage caused by the attack on the target network.',
		'Reference Monitor':
			'A reference monitor monitors the restrictions imposed on the basis of certain access control rules.',
		'Role-Based Access Control (RBAC)':
			'In a role-based access control, the access permissions are available based on the access policies determined by the system.',
		'Rule-based Access Control (RB-RBAC)':
			'Permissions are assigned to a user role dynamically based on a set of rules defined by the administrator.',
		'Recovery Controls':
			'These controls are used in a more serious condition to recover from security violation and restore information and systems to a persistent state.',
		'Research Honeypots':
			'Research honeypots are high-interaction honeypots primarily deployed by research institutes, governments, or military organizations to gain detailed knowledge about the actions of intruders.',
		'Reverse Proxy':
			'A reverse proxy is usually situated closer to the server(s) and will only return a configured set of resources.',
		RFID: 'The radio-frequency identification (RFID) technology uses radio frequency (RF) electromagnetic waves to transfer data for automatic identification and for tracking tags attached to objects.',
		'Reflector Antennas':
			'Reflector antennas are used for concentrating electromagnetic energy that is radiated or received at a focal point.',
		RADIUS:
			'Remote authentication dial-in user service (RADIUS) is an authentication protocol which provides centralized authentication, authorization, and accounting (AAA) for remote access servers to communicate with a central server.',
		'Retinal Scanning':
			'Analyzes the layer of blood vessels at the back of their eyes to identify a person.',
		'Regulatory Frameworks':
			'IT security regulatory frameworks contain a set of guidelines and best practices.',
		'Real-time–based IDS':
			'Real-time–based IDS gathers and monitors information from network traffic streams regularly.',
		'Response System':
			'The response system issues countermeasures against any intrusion that is detected.',
		Registry: 'A registry contains all images that an organization deploys.',
		'Real-time Monitoring':
			'Real-time monitoring involves monitoring IoT assets, processing products, maintaining a flow, helping detect issues, and taking actions immediately.',
		'Real-time Analytics':
			'Real-time analytics involves analyzing IoT things and taking steps accordingly.',
		'Redundant Array of Independent Disks (RAID) Technology':
			'A method of combining multiple hard drives into a single unit and writing data across several disk drives, offering fault tolerance.',
		'RAID Controller':
			'Manages an array of physical disk drives and presents them to the computer as logical units.',
		'RAID Level 0':
			'Disk Striping: RAID 0 deals with data performance. In this level, data is broken into sections and written across multiple drives.',
		'RAID Level 1':
			'Disk Mirroring: Multiple copies of data are written to multiple drives at the same time.',
		'RAID Level 3':
			'Disk Striping with Parity: Data is striped at the byte level across multiple drives. One drive per set is taken up for parity information.',
		'RAID Level 5':
			'Block Interleaved Distributed Parity: The data is striped at the byte level across multiple drives, and the parity information is distributed among all the member drives.',
		'RAID Level 10':
			'Blocks Striped and Mirrored: RAID 10 is a combination of RAID 0 (striping volume data) and RAID 1 (disk mirroring), and its implementation requires at least four drives.',
		'RAID Level 50':
			'Mirroring and Striping across Multiple RAID Levels: RAID level 50 includes mirroring and striping across multiple RAID levels.',
		'Remote Wipe':
			'Remote wipe is a technique used for securing and protecting data from miscreants if a mobile device used by an employee was stolen or lost.',
		RC4: 'RC4 is a variable key-size symmetric-key stream cipher with byte-oriented operations, and it is based on the use of a random permutation.',
		RC5: 'It is a parameterized algorithm with a variable block size, variable key size, and variable number of rounds. The key size is 128 bits.',
		RC6: 'It is a parameterized algorithm with a variable block size, key size, and number of rounds.',
		'Rivest-Shamir-Adleman (RSA)':
			'RSA is an Internet encryption and authentication system that uses an algorithm developed by Ron Rivest, Adi Shamir, and Leonard Adleman.',
		'Removable Media Encryption':
			'Removable media encryption prevents removable media devices from unauthorized access.',
		'Reconnaissance Traffic Signatures':
			'Reconnaissance traffic consists of signatures that indicate an attempt to scan the network for possible weaknesses.',
	},
	S: {
		'Secure/Multipurpose Internet Mail Extensions (S/MIME)':
			'S/MIME is an application layer protocol which is used for sending digitally signed and encrypted email messages.',
		'Secure Sockets Layer (SSL)':
			'The secure sockets layer (SSL) is a protocol used for providing a secure authentication mechanism between two communicating applications such as a client and a server.',
		Subject:
			'A subject can be defined as a user or a process that attempts to access the objects.',
		'Separation of Duties (SoD)':
			'This involves a breakdown of the authorization process into various steps.',
		'Smart Card Authentication':
			'A smart card consists of a small computer chip that stores personal information of the user for identification.',
		'Single Sign-on (SSO) Authentication':
			'It allows the users to access multiple applications using a single username and password.',
		'Sarbanes Oxley Act (SOX)':
			'The Sarbanes-Oxley Act is designed to protect investors and the public by increasing the accuracy and reliability of corporate disclosures.',
		'Security Policy':
			'A security policy is a well-documented set of plans, processes, procedures, standards, and guidelines required to establish an ideal information security status of an organization.',
		'System Specific Security Policy (SSSP)':
			'SSSP directs users while configuring or maintaining a system.',
		'Software Firewalls':
			'A software firewall is a software program installed on a computer, just like normal software.',
		'Stateful Multilayer Inspection Firewall':
			'A stateful multilayer inspection firewall combines the aspects of the other three types.',
		'Signature Recognition':
			'Signature recognition, also known as misuse detection, tries to identify events that indicate an abuse of a system or network resource.',
		'Secure Hypertext Transfer Protocol (S-HTTP)':
			'Secure hypertext transfer protocol (S-HTTP) is an application layer protocol that is used to encrypt web communications carried over HTTP.',
		Standards:
			'Standards comprise specific low-level mandatory controls or controls related to the implementation of a specific technology.',
		'Single-homed Bastion Host':
			'A firewall device with only one network interface.',
		'Single Firewall DMZ':
			'In this model, the network architecture containing the DMZ consists of three network interfaces.',
		'Spam Honeypots':
			'Spam honeypots specifically target spammers who abuse vulnerable resources such as open mail relays and open proxies.',
		'Spider Honeypots':
			'Spider honeypots are also called spider traps. These honeypots are specifically designed to trap web crawlers and spiders.',
		'SOCKS Proxy':
			'SOCKS, an Internet Engineering Task Force (IETF) standard, is a proxy server that does not have the special caching abilities of a caching HTTP proxy server.',
		'Site-to-Site VPNs':
			"Site-to-site VPN extends the company's network, allows access of an organization's network resources from different locations.",
		'Software VPNs':
			'VPN software is installed and configured on routers, servers and firewalls or as a gateway that functions as a VPN.',
		'Star Topology':
			'Each device on the network is connected to a central hub that manages the traffic through the network.',
		'Storage Device Virtualization':
			'This is the virtualization of storage devices using techniques such as data striping and data mirroring.',
		'Server Virtualization':
			'This involves the logical partitioning of the server’s hard drive.',
		Sandbox:
			'This contains the configuration of a container’s network stack such as routing table, management of container’s interfaces, and DNS settings.',
		'Security Incident and Event Management (SIEM)':
			'SIEM performs real-time SOC (Security Operations Center) functions like identifying, monitoring, recording, auditing, and analyzing security incidents.',
		'Software-as-a-Service (SaaS)':
			'This cloud computing service offers software to subscribers on-demand over the Internet.',
		'Security-as-a-Service (SECaaS)':
			'This cloud computing model integrates security services into corporate infrastructure in a cost-effective way.',
		'Service Set identifier (SSID)':
			'An SSID is a 32-alphanumeric-character unique identifier given to a WLAN that acts as a wireless identifier of the network.',
		'Shared Responsibility':
			'Security is a shared responsibility in cloud systems, wherein the cloud consumers and cloud service providers have varying levels of control over the available computing resources.',
		'Shared Key Authentication':
			'In this process, each wireless station receives a shared secret key over a secure channel that is distinct from the 802.11 wireless network communication channels.',
		'Simple Network Management Protocol (SNMP) Polling':
			'Simple network management protocol (SNMP) polling is used for identifying the IP devices attached to a wired network.',
		SDRAM:
			'Dynamic Random Access memory (DRAM) that is synchronized with the CPU clock speed.',
		'Storage Area Network (SAN)':
			'A SAN is a specialized, dedicated, and discrete high-speed network that connects storage devices with a high speed I/O interconnect.',
		'System Access Controls':
			'System access controls are used for the restriction of access to data according to sensitivity of data, clearance level of users, user rights, and permissions.',
		'Secure VPNs': 'Secure VPNs are networks constructed using encryption.',
		'Security Monitoring':
			'To address security breaches at early stages and to prevent malicious attacks on an IoT system.',
		SATA: 'Serial ATA deals with hot plugging and serial connectivity. The hot plugging technique may be used to replace computer components without shutting down the system.',
		SCSI: 'Small computer system interface (SCSI) allows multiple devices to be connected to a single port at the same time.',
		'Satellite Communication (Satcom)':
			'Satcom is an artificial geostationary satellite that provides services across the globe, but it is much slower.',
		'Screen Lock':
			'Screen lock is a feature in mobile devices that is used to secure data and prevent illegal access by perpetrators.',
		'Symmetric Encryption':
			'Symmetric encryption requires that both the sender and the receiver of the message possess the same encryption key.',
		'Secure Hashing Algorithm (SHA)':
			'This algorithm generates a cryptographically secure one-way hash; it was published by the National Institute of Standards and Technology as a US Federal Information Processing Standard.',
		'SHA-1':
			'It produces a 160-bit digest from a message with a maximum length of (264 − 1) bits, and it resembles the MD5 algorithm.',
		'SHA-2':
			'It is a family of two similar hash functions with different block sizes, namely, SHA-256, which uses 32-bit words, and SHA-512, which uses 64-bit words.',
		'SHA-3':
			'SHA-3 uses the sponge construction, in which message blocks are XORed into the initial bits of the state, which is then invertibly permuted.',
	},
	T: {
		'Transport Layer Security (TLS)':
			'TLS ensures a secure communication between client-server applications over the internet.',
		'Two-factor Authentication':
			'Two-factor authentication is a process where a system confirms the user identification in two steps.',
		'The Digital Millennium Copyright Act (DMCA)':
			'The DMCA is a United States copyright law that implements two 1996 treaties of the World Intellectual Property Organization (WIPO).',
		'The Federal Information Security Management Act (FISMA)':
			'The FISMA provides a comprehensive framework for ensuring the effectiveness of information security controls over information resources that support Federal operations and assets.',
		'The Electronic Communications Privacy Act':
			'The Electronic Communications Privacy Act and the Stored Wire Electronic Communications Act are commonly referred together as the Electronic Communications Privacy Act (ECPA) of 1986.',
		'The Human Rights Act 1998':
			'This Act buttresses the rights and freedoms guaranteed under the European Convention on Human Rights.',
		'The Freedom of Information Act 2000':
			'This Act makes provision for the disclosure of information held by public authorities or by persons providing services for them and to amend the Data Protection Act 1998 and the Public Records Act 1958.',
		'TACACS+':
			'TACACS+ provides authentication, authorization, and accounting (AAA) services for network communication.',
		'True Positive (Attack - Alert)':
			'A true positive is a condition that occurs when an event triggers an alarm and causes the IDS to react as if a real attack is in progress.',
		'True Negative (No attack - No Alert)':
			'A true negative is a condition that occurs when an IDS identifies an activity as acceptable behavior, and the activity is acceptable.',
		'Transparent Proxy':
			'A transparent proxy is a proxy through which a client system connects to a server without its knowledge.',
		'Technical Security Controls':
			'Technical security controls are used for restricting access to devices in an organization to protect the integrity of sensitive data.',
		Turnstiles:
			'This type of physical barrier allows entry to only one person at a time.',
		TKIP: 'It is a security protocol used in WPA as a replacement for WEP.',
	},
	U: {
		'User Identity Management (IDM)':
			'Deals with confirming the identity of a user, process, or device accessing the network.',
		'User Behavior Analytics (UBA)':
			'UBA is the process of tracking user behavior to detect malicious attacks, potential threats, and financial fraud.',
		'Universal Serial Bus (USB)':
			'USB enables wired communication for devices. It can be used for power supply and serial data transmission between devices.',
		'USA Patriot Act 2001':
			'The purpose of the USA PATRIOT Act is to deter and punish terrorist acts in the U.S. and around the world and enhance law enforcement investigatory tools.',
		'Unauthorized Access Traffic Signatures':
			'Traffic containing certain signatures that indicate an attempt to gain unauthorized access.',
	},
	V: {
		'Video Surveillance':
			'Video surveillance refers to monitoring activities in and around the premises using CCTV (Close Circuit Television) systems.',
		'Vein Structure Recognition':
			'Analyzes thickness and location of veins to identify a person.',
		'Voice Recognition':
			'Compares and identifies a person on the basis of the voice patterns or speech patterns.',
		'Virtual Private Network':
			'A VPN is a private network constructed using public networks, such as the Internet.',
		'VPN Topologies':
			'A VPN topology specifies how the peers and networks within a VPN are connected.',
		Virtualization:
			'Virtualization refers to a software-based virtual representation of an IT infrastructure that includes network, devices, applications, storage, etc.',
		'VPN Concentrators':
			'A VPN Concentrator is a network device used to create secure VPN connections.',
	},
	W: {
		'Warning Signs':
			'Warning signs are used to ensure someone does not inadvertently intrude in any restricted areas.',
		'Wi-Fi':
			'It uses radio waves or microwaves to allow electronic devices to exchange data or connect to the Internet.',
		WiMAX:
			'The worldwide interoperability for microwave access (WiMAX) technology uses long distance wireless networking and high-speed Internet.',
		WLAN: 'It connects users in a local area with a network. The area may range from a single room to an entire campus.',
		WWAN: 'WWAN covers an area larger than the WLAN. It can cover a particular region, nation, or even the entire globe.',
		WPAN: 'It interconnects devices positioned around an individual, in which the connections are wireless. It has a very short range.',
		WMAN: 'It accesses broadband area networks by using an exterior antenna. It is a good alternative for a fixed-line network.',
		'Wireless Networks':
			'Wireless networks use radio frequency (RF) signals to connect wireless-enabled devices in a network.',
		'Wired Network Scanning':
			'Wired network scanners such as Nmap are used for identifying a large number of devices on a network by sending specially crafted TCP packets to the device (Nmap-TCP fingerprinting).',
		'Wireless Network Cards (NIC)':
			'Wireless network interface cards (NICs) are cards that locate and communicate to an AP with a powerful signal, giving network access to the users.',
		'Wireless Modem':
			'A wireless modem is a device that allows PCs to connect to a wireless network and access the Internet connection directly with the help of an ISP.',
		'Wireless Bridge':
			'A wireless bridge connects multiple LANs at the medium access control (MAC) layer.',
		'Wireless Repeater (range expanders)':
			'This device retransmits the existing signal captured from the wireless router or an AP to create a new network.',
		'Wireless Router':
			'A wireless router is a device in a WLAN which interconnects two types of networks using radio waves to the wireless enabled devices such as computers, laptops, and tablets.',
		'Wireless Gateways':
			'A wireless gateway is a key component of a wireless network. It is a device that allows Internet-enabled devices to access the network.',
		'Wireless Scanning':
			'It performs an active wireless network scanning to detect the presence of wireless APs in the vicinity.',
		'Wireless USB Adapter':
			'A wireless USB adapter connects different devices to a wireless network in order to access the Internet without a computer, router, or any other network device.',
		'Wired Equivalent Privacy (WEP)':
			'WEP is a security protocol defined by the 802.11b standard; it was designed to provide a wireless LAN with a level of security and privacy comparable to that of a wired LAN.',
		'Wi-Fi Protected Access (WPA)':
			'It is an advanced wireless encryption protocol using TKIP and Message Integrity Check (MIC) to provide strong encryption and authentication.',
		WPA2: 'WPA2 is an upgrade to WPA, and it includes mandatory support for counter mode with cipher block chaining message authentication code protocol (CCMP), an AES-based encryption mode with strong security.',
		'WPA2 Enterprise': 'Integrates EAP standards with WPA2 encryption.',
		WPA3: 'WPA3 is an advanced implementation of WPA2 providing trailblazing protocols and uses the AES-GCMP 256 encryption algorithm.',
		'Windows Information Protection (WIP)':
			'WIP has an endpoint data loss prevention (DLP) capability that can be helpful in protecting local data at rest on endpoint devices.',
		'Warm Backup (Nearline)':
			'A warm backup is also called a nearline backup. In a warm backup, the system updates are turned on to receive periodic updates.',
	},
	X: {},
	Y: {
		'Yagi antenna':
			'Yagi antenna, also called as the Yagi-Uda antenna, is a unidirectional antenna commonly used in communications using the frequency band from 10 MHz to very high frequency (VHF) and ultra-high frequency (UHF).',
	},
	Z: {},
};

export default networkDefense;
