package org.zaproxy.addon.cwe400scanner;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.AbstractPanel;

import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.Font;

public class ExtensionCwe400Scanner extends ExtensionAdaptor {
    public static final String NAME = "ExtensionCwe400Scanner";
    
    private static JTextArea logArea;
    private static JTextField txtMaxThreads;
    private AbstractPanel statusPanel;

    public ExtensionCwe400Scanner() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new BorderLayout());
            statusPanel.setName("CWE-400 Logs");

            long maxMemoryBytes = Runtime.getRuntime().maxMemory();
            int safeLimitByRam = (int) (maxMemoryBytes / (1024 * 1024 * 4)); 

            JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
            toolBar.add(new JLabel("Max Threads: "));
            
            txtMaxThreads = new JTextField("50", 5); 
            toolBar.add(txtMaxThreads);
            
            JLabel lblHint = new JLabel("(Suggested safe limit by your RAM: " + safeLimitByRam + ")");
            lblHint.setForeground(Color.GRAY);
            toolBar.add(lblHint);
            
            statusPanel.add(toolBar, BorderLayout.NORTH);

            logArea = new JTextArea();
            logArea.setEditable(false);
            logArea.setBackground(Color.WHITE);
            logArea.setForeground(Color.BLACK);
            logArea.setFont(new Font("Monospaced", Font.PLAIN, 24));
            
            JScrollPane scrollPane = new JScrollPane(logArea);
            statusPanel.add(scrollPane, BorderLayout.CENTER);
        }
        return statusPanel;
    }

    public static int getUserMaxThreads() {
        try {
            return Integer.parseInt(txtMaxThreads.getText());
        } catch (Exception e) {
            return 50; 
        }
    }

    public static void log(String message) {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(message + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }

    @Override
    public boolean canUnload() { return true; }
}