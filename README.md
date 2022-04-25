# McAfee-stuff  

## McAfee Agent Real Agent Compliance  

The Real Agent Compliance script fetches the last check-in date for all agents from the ePO via API. 
It then fetches all last logons from all systems from the Active Directory. The list is cleaned so that only those systems are compared, that really exist in the ePO. 
If there is a missmatch in the dates, e.g. a system logged on to the AD, but the agent didn't to the ePO, we know we have a problem with the agent. If this is the case, the system gets a custom TAG (needs to be created in ePO beforehand) assigned. You can then have sheduled reports and queries that will give you an overview of the affected devices as an e-mail report or in the dashboard.  
