module com.saaiqsas.purplekrypt {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.desktop;
    requires org.bouncycastle.provider;


    opens com.saaiqsas.purplekrypt to javafx.fxml;
    exports com.saaiqsas.purplekrypt;
}