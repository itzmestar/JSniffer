package jsniffer;

import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.NifSelector;

import com.sun.jna.Platform;

import java.net.Inet4Address;

@SuppressWarnings("javadoc")
public class PacketSniffer {

  private static final String COUNT_KEY
    = PacketSniffer.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, -1); // -1 -> loop infinite

  private static final String READ_TIMEOUT_KEY
    = PacketSniffer.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 100); // [ms]

  private static final String SNAPLEN_KEY
    = PacketSniffer.class.getName() + ".snaplen";
  private static final int SNAPLEN
    = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // defines the header
  private final	String[] header = {"S. No.", "Timestamp", 
			"Source IP", "Destination IP","Src Port","Dst Port","Protocol","Packet Length (Byte)","Info"};

  private PcapNetworkInterface nif=null;
  PcapHandle handle=null;
  
  int pktCount = 0;
  PacketTable packetTable=null;
  int captureTime = 60; //seconds
  
  Timer timer = new Timer();
  
  private PacketSniffer(PcapNetworkInterface nif) {
	  this.nif = nif;
	  displayTable();
  }

  PacketListener listener
      = new PacketListener() {
          @Override
          public void gotPacket(Packet packet) {
            //System.out.println(handle.getTimestamp());
            //System.out.println(packet);
              printPacket(packet, handle.getTimestamp().toString());
          }
   };
 
   //Packet count increment 
   synchronized private void incrementCount(){
	   pktCount++;
   }
   
   //get the packet count
   synchronized private int getPacketCount(){
	   return pktCount;
   }
   
 //print the packet details
 public void printPacket(Packet packet, String timestamp){
     String srcIp, dstIp;
     int srcPort=0, dstPort=0;
     String info="";

     //do nothing if not an IP packet
     if (!packet.contains(IpPacket.class)) {
         return;
     }

     //get the IP packet class
     IpPacket ipPacket = packet.get(IpPacket.class);
     srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress().toString();
     dstIp = ipPacket.getHeader().getDstAddr().getHostAddress().toString(); 
     //int srcPort = ipv4packet.getHeader().
     //}

     String proto= ipPacket.getHeader().getProtocol().name();
     
     if (proto.equals("TCP") ){
         TcpPacket tcpPkt = packet.get(TcpPacket.class);
         srcPort = tcpPkt.getHeader().getSrcPort().valueAsInt();
         dstPort = tcpPkt.getHeader().getDstPort().valueAsInt();
     }else if (proto.equals("UDP") ){
         UdpPacket udpPkt = packet.get(UdpPacket.class);
         srcPort = udpPkt.getHeader().getSrcPort().valueAsInt();
         dstPort = udpPkt.getHeader().getDstPort().valueAsInt();
     }else{
         return;
     }
     
     //find if its HTTP packet
     if (srcPort == 80 || srcPort == 8080 || dstPort == 80 || dstPort == 8080 ){
    	 proto = "HTTP";
     }else if(srcPort == 443 || dstPort == 443 ){
    	 proto = "HTTPS";
     }
     int len = packet.length();
     
     //print the header
     if(getPacketCount()==0){
    	 System.out.print("\n|---------------------------------------------------------------------------|");
         System.out.print("\n|S.N.|Timestamp|Source IP|Destination IP|Src Port|Dst Port|Proto|Len|Info|");
     }
     //increment the count
     incrementCount();
     
     //print the details of packet
     System.out.print("\n| "+getPacketCount()+" |"+timestamp+"|");
     System.out.print(srcIp+"|"+dstIp+"| ");
     System.out.print(srcPort+" | "+dstPort+" |"+proto+"|"+len+"|");
     
     packetTable.model.add(String.valueOf(getPacketCount()),timestamp,srcIp,dstIp,String.valueOf(srcPort),String.valueOf(dstPort),String.valueOf(proto),String.valueOf(len),info);
     
  }
 
 //Print Final stats
 void printStat(){
    PcapStat ps;
    try {
	ps = handle.getStats();
	 System.out.println("Packets Received: " + ps.getNumPacketsReceived());
	 System.out.println("Packets Dropped: " + ps.getNumPacketsDropped());
	 System.out.println("Packets Dropped By Intf: " + ps.getNumPacketsDroppedByIf());
	 if (Platform.isWindows()) {
        	 System.out.println("Packets Captured: " + ps.getNumPacketsCaptured());
	 }	
	} catch (PcapNativeException | NotOpenException e) {
		// Auto-generated catch block
		e.printStackTrace();
	}
 
 }
 
 //start capturing the packets
  void startSniffing(){
    try{
        handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        System.out.println("\nRunning for time:"+captureTime+"seconds");
        startTimer();
        handle.loop(COUNT, listener);
        
        
    } catch(PcapNativeException e){
        e.printStackTrace();  
    }
    catch (InterruptedException e) {
      //e.printStackTrace();
    }
    catch (NotOpenException e) {
      e.printStackTrace();
    }
    finally{
        printStat();
        handle.close();
        timer.cancel();
    }
  }
  
  //stop capturing the packets
  void stopSniffing(){
    System.out.println("\nStopping Sniffing...\n");
    try {
        handle.breakLoop();
    } catch (NotOpenException e) {
			// Auto-generated catch block
	e.printStackTrace();
    }
 }
  
//Display the Packet Table GUI
  void displayTable(){
	  // defines rows and column of the JTable
	  String[][] rowAndColumn = {
	  };
    
	  packetTable = new PacketTable(rowAndColumn, header);  
  }
  
  //set the capture time
  void setTime(int t){
      captureTime = t > 0 ? t : 60;
  }
  
  //Start timer
  void startTimer(){
    timer.schedule(new TimerTask() {
    @Override
    public void run() {
        stopSniffing();
    }
    }, captureTime*1000);    
  }
  
  public static void main(String[] args) throws PcapNativeException, NotOpenException {

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    System.out.println(nif.getName() + "(" + nif.getDescription() + ") Selected!");

    PacketSniffer packetSniffer = new PacketSniffer(nif);
    if (args.length>0){
        int time= Integer.parseInt(args[0]);
        packetSniffer.setTime(time);
    }
    
    packetSniffer.startSniffing();
  }

}