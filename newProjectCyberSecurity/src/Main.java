import javax.swing.*;
import java.awt.*;


/**
 * Created by Franck on 14.11.2017.
 */

public class Main {
    public static void main(String[] args) throws InterruptedException {
        JFrame frame = new JFrame("Deffie-Hellman");
        frame.setSize(800, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setLayout(new GridBagLayout());


        SideA sideA = new SideA();
        SideB sideB = new SideB();
        Spy spy = new Spy();

        sideA.generateSecretKey(sideB, spy);


        System.out.println("SideA generates parameters a, p, g and A and sends them to sideB");
        System.out.println("Spy intercepts parameters a, p, g and A from sideA and generates privat parameter c");
        System.out.println("SideB recieves parameters a, p, g and A from sideA and generates privat parameter b");

        System.out.println();

        System.out.println("SideB generates key based on parameters p, g, b and A");

        System.out.println("SideB send public key B to side A");
        System.out.println("Spy intercepts public key B from sideB which oriented for sideA");

        System.out.println();

        System.out.println("SideA recieves public key B from sideA and generates sercet key based on parameters p, g, a and B");
        System.out.println("Spy generates private key as it exchanged sideB base on parameters p, g, c and A");
        System.out.println("Spy generates private key as it exchanged sideA base on parameters p, g, c and B");

        System.out.println();

        System.out.println("Have a look at generated private keys of each participents:");
        System.out.print("sideA:                     ");
        sideA.showHashSecretKey();
        System.out.print("sideB:                     ");
        sideB.showHashSecretKey();
        System.out.print("spy as it exchanges sideB: ");
        spy.showHashSecretKey();

        System.out.println();





        JButton sendButton = new JButton();
        sendButton.setText("Send");

        JTextField textFieldMessage= new JTextField(30);




        textFieldMessage.setText("few");
        JLabel label = new JLabel("Alise");
        Font font = new Font("Veranda", Font.ITALIC, 25);
        JProgressBar progressBar = new JProgressBar();
        progressBar.setStringPainted(false);
        progressBar.setIndeterminate(true);
        progressBar.setMinimum(0);
        progressBar.setMaximum(1000);
        frame.add(progressBar);
        for(int i = progressBar.getMinimum(); i <= progressBar.getMaximum(); i++) {
            Thread.sleep(5);
        }
        label.setFont(font);

        JPanel panel = new JPanel();
        panel.setBackground(Color.BLACK);
        panel.setVisible(true);
        frame.add(panel);
        frame.add(label);
        frame.add(textFieldMessage);
        frame.add(sendButton);

        frame.setVisible(true);
        Thread.sleep(4000);


        String testMessage = textFieldMessage.getText();
        System.out.println("SideA enciphers message " + testMessage);

        String encipheredMessage = sideA.encipherMessage(testMessage);
        System.out.println();
        System.out.println("Message was enchiphered and now looks like: " + encipheredMessage);
        System.out.println();
        String decipheredMessage = sideB.decipherMessage(encipheredMessage);
        System.out.println("SideB deciphers message: " + decipheredMessage);
        System.out.println();

        String decipheredMessageBySpy = spy.decipherMessage(encipheredMessage);
        System.out.println("Spy deciphers message as it exchanges sideB: " + decipheredMessageBySpy);









    }

}
