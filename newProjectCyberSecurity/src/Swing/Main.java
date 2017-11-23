package Swing;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by Franck on 15.11.2017.
 */
public class Main {
    static JLabel textBob;
    static JTextField textFieldMessage;
    public static void main(String[] args) throws InterruptedException {
        JFrame frame = new JFrame("Deffie-Hellman");
        frame.setSize(800, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setLayout(new GridLayout(2, 3));







        JButton sendButton = new JButton();
        sendButton.setText("Send");

        textFieldMessage= new JTextField(30);
        textFieldMessage.setText("few");

        JLabel labelAlise = new JLabel("Alise");
        Font font = new Font("Veranda", Font.ITALIC, 25);
        JProgressBar progressBar = new JProgressBar();
        progressBar.setStringPainted(false);
        progressBar.setIndeterminate(true);
        progressBar.setMinimum(0);
        progressBar.setMaximum(1000);
        for(int i = progressBar.getMinimum(); i <= progressBar.getMaximum(); i++) {
            Thread.sleep(5);
        }
        labelAlise.setFont(font);
        JLabel labelBob = new JLabel("Bob");
        labelBob.setFont(font);
        JLabel labelSpy = new JLabel("Spy");
        labelSpy.setFont(font);
        textBob = new JLabel("Bob text:");
        labelBob.setFont(font);
        JLabel textSpy = new JLabel("Spy text:");
        labelSpy.setFont(font);
        JLabel textAlise = new JLabel("Alise text:");
        labelSpy.setFont(font);

        JPanel panelAlise = new JPanel();
        panelAlise.setLayout(new GridLayout(2,1));
        panelAlise.add(labelAlise);
        panelAlise.setBackground(Color.BLUE);
        panelAlise.add(textAlise);
        JPanel panelBob = new JPanel();
        panelBob.setLayout(new GridLayout(2,1));
        panelBob.add(labelBob);
        panelBob.setBackground(Color.GREEN);
        panelBob.add(textBob);
        JPanel panelSpy = new JPanel();
        panelSpy.setLayout(new GridLayout(3,1));
        panelSpy.add(labelSpy);
        panelSpy.add(progressBar);
        panelSpy.setBackground(Color.RED);
        panelSpy.add(textSpy);
        JPanel panelTextMessage = new JPanel();
        JPanel panelRunButton = new JPanel();
        JPanel panelEmplty = new JPanel();
        panelTextMessage.setLayout(new BorderLayout());
        panelTextMessage.add(textFieldMessage, BorderLayout.PAGE_START);
        panelTextMessage.add(sendButton, BorderLayout.CENTER);
        panelAlise.setVisible(true);
        panelBob.setVisible(true);
        panelSpy.setVisible(true);
        panelTextMessage.setVisible(true);
        panelRunButton.setVisible(true);
        panelEmplty.setVisible(true);


        sendButton.addActionListener(new MyButtonActionListener());



        frame.add(panelAlise);
        frame.add(panelSpy);
        frame.add(panelBob);
        frame.add(panelTextMessage);
        frame.add(panelRunButton);
        frame.add(panelEmplty);

        frame.setVisible(true);










    }

    public static class MyButtonActionListener implements ActionListener {


        @Override
        public void actionPerformed(ActionEvent e) {
            textBob.setText(textFieldMessage.getText());
        }
    }
}
