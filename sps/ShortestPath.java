package edu.nyu.cs.sdn.apps.sps;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;

public class ShortestPath {
	
	public Map<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> getPaths(String algo, Map<Long, IOFSwitch> switches, Collection<Link> links){
		if(algo.equals("Bellman_Ford")){
			return BellMan_Ford();
		}
		else{
			return Dijkstra(switches, links);
		}
	}
	
	
	private Map<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> Dijkstra(Map<Long, IOFSwitch> switches, Collection<Link> links){
		Map<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortestDist = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
		Collection<IOFSwitch> switchList = switches.values();
		for(IOFSwitch s: switchList){
			Map<IOFSwitch, Integer> relaxed = new HashMap<IOFSwitch, Integer>();
			Map<IOFSwitch, Integer> remaining = new HashMap<IOFSwitch, Integer>();
			HashMap<IOFSwitch, IOFSwitch> previous = new HashMap<IOFSwitch, IOFSwitch>();
			
			for(IOFSwitch x: switchList){
				relaxed.put(x, 2147483646);
				remaining.put(x, 2147483646);
				previous.put(x, null);
			}
			remaining.put(s,0);
			relaxed.put(s, 0);
			
			
			for(Link l: links){
				if(switches.get(l.getSrc()) != s){
					continue;
				}
				
				relaxed.put(switches.get(l.getDst()), 1);
				remaining.put(switches.get(l.getDst()), 1);
				previous.put(switches.get(l.getDst()), switches.get(l.getSrc()));
			}
			
			Set<IOFSwitch> seen = new HashSet<IOFSwitch>();
			
			while(!remaining.isEmpty()){
				IOFSwitch min = Collections.min(remaining.entrySet(), new Comparator<Map.Entry<IOFSwitch, Integer>>(){
						public int compare(Map.Entry<IOFSwitch, Integer> e1, Map.Entry<IOFSwitch, Integer> e2){
						return e2.getValue().compareTo(e2.getValue());
						}
					}).getKey();
				
				remaining.remove(min);
				seen.add(min);
				
				for(Link l: links){
					if(switches.get(l.getSrc()) != min || seen.contains(switches.get(l.getDst()))){
						continue;
					}
					else if(switches.get(l.getSrc()) == min){
						if(!seen.contains(switches.get(l.getDst()))){
							if(relaxed.get(min) + 1 <relaxed.get(switches.get(l.getDst()))){
								relaxed.put(switches.get(l.getDst()), relaxed.get(min)+1);
								remaining.put(switches.get(l.getDst()), relaxed.get(min)+1);
								previous.put(switches.get(l.getDst()), min);
							}
						}
				}
			}
		}
			
			shortestDist.put(s,previous);
		}
		return shortestDist;
	}
	
	private Map<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> BellMan_Ford(){
		return new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
	}
}
