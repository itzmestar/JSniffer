package jsniffer;

import java.awt.*;
import java.util.*;

import javax.swing.*;
import javax.swing.table.*;

public class PacketTable extends JFrame {

	// the Model in instance variable so we can access it
	MyModel model;
	
	// constructor that will display a JTable based on elements received as arguments
	PacketTable(Object[][] obj, String[] header) {
		super("Packet Sniffer");
		
		// JPanel to hold the JTable
		JPanel panel = new JPanel(new BorderLayout());
		// constructor of JTable model
		model = new MyModel(obj, header);
		// the table from that model
		JTable table = new JTable(model);
                table.setBackground(Color.blue);
                table.setForeground(Color.white);
		panel.add(new JScrollPane(table));
                
		add(panel);    // adding panel to frame
		// and display it
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setVisible(true);
		pack();
	}
	
	// class that extends the AbstractTableModel
	class MyModel extends AbstractTableModel {

		// to store our elements, we will use an ArrayList<Object> for each row
		ArrayList<Object[]> al;
		// the headers
		String[] header;
		
		// constructor 
		MyModel(Object[][] obj, String[] header) {
			// save the header
			this.header = header;	
			// and the rows
			al = new ArrayList<Object[]>();
			// copy the rows into the ArrayList
			for(int i = 0; i < obj.length; ++i)
				al.add(obj[i]);
		}
		// method that needs to be overloaded. The row count is the size of the ArrayList
		public int getRowCount() {
			return al.size();
		}

		// method that needs to be overload. The column count is the size of our header
		public int getColumnCount() {
			return header.length;
		}

		// method that needs to be overload. The object is in the arrayList at rowIndex
		public Object getValueAt(int rowIndex, int columnIndex) {
			return al.get(rowIndex)[columnIndex];
		}
		
		// a method to return the column name 
		public String getColumnName(int index) {
			return header[index];
		}
		
		// a method to add a new line to the table
		void add(String serial, String ts, String srcIP, String dstIP, String srcPort, String dPort, String proto, String len, String info) {
			// make it an array[9] as this is the way it is stored in the ArrayList
			String[] str = new String[9];
                        String space="   ";
			str[0] = space+serial;
			str[1] = space+ts;
			str[2] = space+srcIP;
			str[3] = space+dstIP;
			str[4] = space+srcPort;
			str[5] = space+dPort;
			str[6] = space+proto;
			str[7] = space+len;
			str[8] = space+info;
			al.add(str);
			// inform the GUI that I have change
			fireTableDataChanged();
		}
	}
}
