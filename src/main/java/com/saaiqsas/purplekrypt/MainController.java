package com.saaiqsas.purplekrypt;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.ImageView;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.scene.text.Text;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.converter.IntegerStringConverter;

import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/*
    PurpleKrypt Graphical Tool is Licensed under The GNU GPLv3
    +-----------------------------------------------------------------------+
    | PurpleKrypt -                                                         |
    | An encryption tool for text and file encryption, utilizing the        |
    | AES-256-GCM algorithm. It supports keyfiles and passwords via         |
    | Argon2id key derivation                                               |
    |                                                                       |
    | Copyright (C) 2025-Present Saaiq Abdulla Saeed (saaiqSAS)             |
    |                                                                       |
    | This program is free software: you can redistribute it and/or modify  |
    | it under the terms of the GNU General Public License as published by  |
    | the Free Software Foundation, either version 3 of the License, or     |
    | (at your option) any later version.                                   |
    |                                                                       |
    | This program is distributed in the hope that it will be useful,       |
    | but WITHOUT ANY WARRANTY; without even the implied warranty of        |
    | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the          |
    | GNU General Public License for more details.                          |
    |                                                                       |
    | You should have received a copy of the GNU General Public License     |
    | along with this program. If not, see <https://www.gnu.org/licenses/>. |
    |                                                                       |
    | For support or to contact the author:                                 |
    | Email: purplekrypt@gmail.com                                          |
    +-----------------------------------------------------------------------+
*/

public class MainController implements Initializable {

    protected static byte KEY_FILE_USAGE = 0; // 0:generate 1:select 2:none
    protected static boolean USE_PASSWORD = true;
    protected static byte KEY_USAGE = 99; // 0:gen_unenc_keyfile  1:gen_enc_keyfile  2:sel_unenc_keyfile  3:sel_enc_keyfile  4:password_only
    protected static byte FUNCTION_TYPE = 0; // 0:encrypt  1:decrypt
    protected static byte INPUT_TYPE = 0; // 0:text  1:file
    protected static byte[] PK_AAD_ID = null;
    protected static boolean USE_PK_AAD_ID = false;
    protected static boolean RANDOM_FILE_NAMES = false;
    protected static byte OUTPUT_METHOD = 0; // 0:copy 1:move 2:replace
    protected static int THREADS = 0;

    // Additional
    protected static HashMap<String,DataFileInput_File> FILES_TO_PROCESS = new HashMap<>();
    private static String ID_OF_SELECTED_DATA_FILE = "";
    private static File LAST_VISITED_DIR;

    private static boolean UPDATE_KEY_ON_MEMORY = false;

    protected static String OUTPUT_DIR;
    protected static String COMMON_PATH;

    private static boolean NEXT_BUTTON_DISABLED = false;
    private static boolean PROCESS_BUTTON_DISABLED = false;

    private static boolean PASSWORD_IS_VISIBLE = false;

    // Main Window and UI
    public VBox root;
    public Button keys_tab;
    public Button data_tab;
    public GridPane keys_tab_display;
    public GridPane data_tab_display;

    public Button main_confirm_button;
    private static Button  main_next_button_STATIC;

    public Button main_process_button;
    private static Button main_process_button_STATIC;

    public Text msg_text;
    protected static Text msg_text_STATIC;
    public Text version;

    // Window Top Icons
    public ImageView key_extracted_icon;

    // Function Box
    public Button function_encrypt_button;
    public Button function_decrypt_button;

    // Input Data Type Box
    public Button input_type_text;
    public Button input_type_file;
    public VBox input_text_box;
    public VBox input_file_box;

    // Summary Box
    public TextArea summary;

    // Key File Box
    public VBox key_file_box;
    public HBox key_file_box_header;
    public Button key_file_generate_button;
    public Button key_file_select_button;
    public Button key_file_none_button;
    public TextField key_file_input;
    public Rectangle key_file_rect;
    public Text key_file_input_label;
    public Button key_file_select_from_fs_button;

    // Password Box
    public Button password_yes_button;
    public Button password_no_button;
    public PasswordField password_input;
    public Rectangle password_rect;

    // Data Tab - Text Input
    public TextArea input_text_input_field;
    public TextArea output_text_output_field;
    public VBox output_text_box;

    // Data Tab - File Input
    public HBox input_data_box_header;
    public TableView<DataFileInput_File> input_file_table;
    public TableColumn<DataFileInput_File,String> input_file_table_name;
    public TableColumn<DataFileInput_File,String> input_file_table_type;
    public VBox output_file_box;
    public VBox output_dir_box;
    public HBox output_dir_box_header;
    public TextField output_directory_file_input;
    public Button input_file_remove_button;
    public VBox input_data_box;

    // Process Settings
    public TextField proc_sett_threads_input;
    public Button use_pk_aad_id_checkbox;
    public Button random_file_names_checkbox;
    public TextField proc_sett_threads_per_file_input;
    public Button password_input_visibility_button;
    public TextField password_input_text;
    public Button function_icon;
    public Button output_copy_button;
    public Button output_move_button;
    public Button output_replace_button;
    public Button paste_to_clipboard_button;
    public Rectangle output_method_rect;


    // Initialize interface
    public void initialize(URL location, ResourceBundle resources) {
        // --- Basic UI Setup ---
        keys_tab_onAction();
        function_encrypt_button_onAction();
        input_type_file_button_onAction();
        generate_key_button_onAction();
        password_yes_button_onAction();
        output_copy_button_onAction();
        random_file_names_checkbox_onAction();
        input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("disabled_button");

        summary.setDisable(true);
        summary.setWrapText(true);
        summary.setText("Hello there, Welcome to PurpleKrypt (PK).\n\nAn open-source encryption tool you can use to encrypt both Files and Text via the AES-256-GCM Algorithm by using either a Keyfile, or a key derived from a Password via Argon2id, or both.\n\nHelp: Select options for Keyfile and Password, then click 'Confirm'.");


        Platform.runLater(() -> {
            // --- Text Fields to Int only ---
            TextFormatter<Integer> textFormatter_Int_6 = new TextFormatter<>(new IntegerStringConverter(), 4);  // max threads
            TextFormatter<Integer> textFormatter_Int_7 = new TextFormatter<>(new IntegerStringConverter(), 1);  // max threads per file

            proc_sett_threads_input.setTextFormatter(textFormatter_Int_6);
            proc_sett_threads_per_file_input.setTextFormatter(textFormatter_Int_7);


            // --- Text Fields Focus Listeners ---

            key_file_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field");
                    clearLogCondition("Please enter a name for the keyfile");
                }
            });

            proc_sett_threads_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    proc_sett_threads_input.getStyleClass().clear();
                    proc_sett_threads_input.getStyleClass().add("input-field");
                    clearLogCondition("Maximum parallel files to process should be between 1 and 25");
                } else {
                    int input = SAS_PK.stringToInt(proc_sett_threads_input.getText());
                    if (input <= 0) {
                        proc_sett_threads_input.setText("4");
                    } else if (input > 25) {
                        log("Maximum parallel files to process should be between 1 and 25", true);
                        proc_sett_threads_input.getStyleClass().clear();
                        proc_sett_threads_input.getStyleClass().add("input-field-error");
                    }
                }
            });

            proc_sett_threads_per_file_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    proc_sett_threads_per_file_input.getStyleClass().clear();
                    proc_sett_threads_per_file_input.getStyleClass().add("input-field");
                    clearLogCondition("Maximum threads per file should be between 1 and 50");
                } else {
                    int input = SAS_PK.stringToInt(proc_sett_threads_per_file_input.getText());
                    if (input <= 0) {
                        proc_sett_threads_per_file_input.setText("4");
                    } else if (input > 50) {
                        log("Maximum threads per file should be between 1 and 50", true);
                        proc_sett_threads_per_file_input.getStyleClass().clear();
                        proc_sett_threads_per_file_input.getStyleClass().add("input-field-error");
                    }
                }
            });


            // --- Un Movable table columns setup ---
            input_file_table_name.setReorderable(false);
            input_file_table_type.setReorderable(false);


            // --- Data File Input table setup ---
            input_file_table_type.setCellValueFactory(new PropertyValueFactory<>("type"));
            input_file_table_name.setCellValueFactory(new PropertyValueFactory<>("name"));

            input_file_table.setPlaceholder(new Label("( drag and drop directory/folder )"));
            
            input_file_table.setRowFactory(tv -> {
                TableRow<DataFileInput_File> row = new TableRow<>();
                row.setOnMouseClicked(event -> {
                    if (!row.isEmpty() && event.getButton() == MouseButton.PRIMARY) {
                        DataFileInput_File rowData = row.getItem();
                        ID_OF_SELECTED_DATA_FILE = rowData.getID();
                        input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("white_button");
                    }
                });
                return row;
            });

            // --- Variable Initialization ---
            msg_text_STATIC = msg_text;
            main_next_button_STATIC = main_confirm_button;
            main_process_button_STATIC = main_process_button;

            log("Developed by saaiqSAS, Licensed under GNU GPLv3", false);
            version.setText(MainApp.VERSION);

        });
    }

    // main window close button
    @FXML
    protected void main_close_window_button_onAction() {
        Stage stage = (Stage) root.getScene().getWindow();
        SAS_PK.stopAllProcesses();
        stage.close();
        Platform.exit();
        System.exit(0);
    }

    // main window minimize button
    @FXML
    protected void main_minimize_window_button_onAction() {
        Stage stage = (Stage) root.getScene().getWindow();
        stage.setIconified(true);
    }

    // log window open
    @FXML
    protected void log_display_button_onAction() {
        MainApp.showLogWin();
    }

    // help
    @FXML
    protected void help_button_onAction() throws IOException {
        MainApp.goToHelp();
    }



    // keys_tab
    @FXML
    protected void keys_tab_onAction() {
        keys_tab.getStyleClass().clear(); keys_tab.getStyleClass().add("main_tabs_active");
        data_tab.getStyleClass().clear(); data_tab.getStyleClass().add("main_tabs");
        data_tab_display.setVisible(false);
        keys_tab_display.setVisible(true);
        main_process_button.setVisible(false);
        main_confirm_button.setVisible(true);
    }

    // data_tab
    @FXML
    protected void data_tab_onAction() {
        data_tab.getStyleClass().clear(); data_tab.getStyleClass().add("main_tabs_active");
        keys_tab.getStyleClass().clear(); keys_tab.getStyleClass().add("main_tabs");
        keys_tab_display.setVisible(false);
        data_tab_display.setVisible(true);
        main_confirm_button.setVisible(false);
        main_process_button.setVisible(true);
    }



    // main confirm button
    @FXML
    protected void main_confirm_button_onAction() {
        key_file_input.getStyleClass().clear();
        key_file_input.getStyleClass().add("input-field");

        // confirms key usage
        try {
            if (NEXT_BUTTON_DISABLED) return;

            if (KEY_FILE_USAGE == 0 && !USE_PASSWORD) { // Generate keyfile only
                if (key_file_input.getText().isEmpty()) {
                    log("Please set a path to save keyfile", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please set a path to save keyfile");}

                File keyfile = new File(key_file_input.getText());
                if (keyfile.exists()) {
                    log("Keyfile already exists", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Keyfile already exists");}

                KEY_USAGE = 0;
                updateSummary(KEY_USAGE);

            } else if (KEY_FILE_USAGE == 0 && USE_PASSWORD) { // Generate Password encrypted keyfile
                if (key_file_input.getText().isEmpty()) {
                    log("Please set a path to save keyfile", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please set a path to save keyfile");}

                File keyfile = new File(key_file_input.getText());
                if (keyfile.exists()) {
                    log("Keyfile already exists", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Keyfile already exists");}

                if (getPassword().isEmpty()) {
                    log("Please enter a password to encrypt keyfile", true);
                    password_input.getStyleClass().clear();
                    password_input.getStyleClass().add("input-field-error");
                    password_input_text.getStyleClass().clear();
                    password_input_text.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please enter a password to encrypt keyfile");}
                KEY_USAGE = 1;
                updateSummary(KEY_USAGE);

            } else if (KEY_FILE_USAGE == 1 && !USE_PASSWORD) { // Select unencrypted keyfile
                if (key_file_input.getText().isEmpty()) {
                    log("Please set a path to a (.pkk) keyfile", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please set a path to a (.pkk) keyfile");}

                File keyfile = new File(key_file_input.getText());
                if (!keyfile.exists()) {
                    log("Keyfile not found", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Keyfile not found");}
                KEY_USAGE = 2;
                updateSummary(KEY_USAGE);

            } else if (KEY_FILE_USAGE == 1 && USE_PASSWORD) { // Select Password encrypted keyfile
                if (key_file_input.getText().isEmpty()) {
                    log("Please set a path to a (.pkk) keyfile", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please set a path to a (.pkk) keyfile");}

                File keyfile = new File(key_file_input.getText());
                if (!keyfile.exists()) {
                    log("Keyfile not found", true);
                    key_file_input.getStyleClass().clear();
                    key_file_input.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Keyfile not found");}

                if (getPassword().isEmpty()) {
                    log("Please enter the password for the selected keyfile", true);
                    password_input.getStyleClass().clear();
                    password_input.getStyleClass().add("input-field-error");
                    password_input_text.getStyleClass().clear();
                    password_input_text.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please enter the password for the selected keyfile");}
                KEY_USAGE = 3;
                updateSummary(KEY_USAGE);

            } else if (KEY_FILE_USAGE == 2 && USE_PASSWORD) { // No keyfile, use Password only
                if (getPassword().isEmpty()) {
                    log("Please enter password for encrypting/decrypting data", true);
                    password_input.getStyleClass().clear();
                    password_input.getStyleClass().add("input-field-error");
                    password_input_text.getStyleClass().clear();
                    password_input_text.getStyleClass().add("input-field-error");
                    return;
                } else {clearLogCondition("Please enter password for encrypting/decrypting data");}
                KEY_USAGE = 4;
                updateSummary(KEY_USAGE);

            } else {return;}

            // clear error on text input boxes
            password_input.getStyleClass().clear();
            password_input.getStyleClass().add("input-field");
            password_input_text.getStyleClass().clear();
            password_input_text.getStyleClass().add("input-field");
            key_file_input.getStyleClass().clear();
            key_file_input.getStyleClass().add("input-field");


            // confirmed inputs will be used when processing
            SAS_PK.KEYFILE = new File(key_file_input.getText());
            SAS_PK.PASSWORD = getPassword().toCharArray();
            UPDATE_KEY_ON_MEMORY = true;

            log("Confirmed keyfile and password usage",false);
            data_tab_onAction();

        } catch (Exception e) {
           MainApp.logToLogWin("[!] An unexpected error has occurred after clicking 'Confirm' button:\n"+ e + "\n");
        }
    }
    
    protected static void enable_confirm_process_button() {
        main_next_button_STATIC.getStyleClass().clear();  main_next_button_STATIC.getStyleClass().add("blue_button");
        PROCESS_BUTTON_DISABLED = false;
        
        main_process_button_STATIC.getStyleClass().clear(); main_process_button_STATIC.getStyleClass().add("blue_button");
        NEXT_BUTTON_DISABLED = false;
        
    }
    
    private void disable_confirm_process_button() {
        main_confirm_button.getStyleClass().clear(); main_confirm_button.getStyleClass().add("disabled_button");
        PROCESS_BUTTON_DISABLED = true;

        main_process_button.getStyleClass().clear(); main_process_button.getStyleClass().add("disabled_button");
        NEXT_BUTTON_DISABLED = true;
    }

    private void updateSummary(byte i) {
        switch (i) {
            case 0 ->    summary.setText("Keyfile: Generate\nPassword: None\n\nNote: Generated key will be stored unencrypted in the keyfile.");
            case 1 ->    summary.setText("Keyfile: Generate\nPassword: Use\n\nNote: Generated key will be stored in the keyfile after encrypting it with a key derived from the password.");
            case 2 ->    summary.setText("Keyfile: Select\nPassword: None\n\nAssumption: Selected keyfile contains an unencrypted key.");
            case 3 ->    summary.setText("Keyfile: Select\nPassword: Used\n\nAssumption: Selected keyfile is a password encrypted key. Thus, provided password should be used to decrypted the keyfile");
            case 4 ->    summary.setText("Keyfile: None\nPassword: Use\n\nNote: Key derived from the provided password will be used to encrypt or decrypt data, without using a keyfile.");

        }

    }

    // main process button
    @FXML
    protected void main_process_button_onAction() {
        try {
            if (PROCESS_BUTTON_DISABLED) {
                return;
            }

            new Thread(() -> {
                clearLog();

                if (KEY_USAGE == 99) {
                    log("Confirm keyfile and password usage first", true);
                    keys_tab_onAction();
                    return;
                }
                if (INPUT_TYPE == 0 && input_text_input_field.getText().isEmpty()) { // text
                    log("Provide text to process first", true);
                    return;
                } else if (INPUT_TYPE == 1 & FILES_TO_PROCESS.isEmpty())  { // files
                    log("Add files to process first",true);
                    return;
                }

                // Setup key
                if (UPDATE_KEY_ON_MEMORY) {
                    log("Setting up key...", false);
                   MainApp.logToLogWin("[*] Setting up key...\n");
                    disable_confirm_process_button();

                    long s1 = System.currentTimeMillis();
                    SAS_PK.KEY = null;
                    try {
                        switch (KEY_USAGE) {
                            case 0 -> // gen keyfile, no pass
                                    SAS_PK.KEY = SAS_PK.generateKeyFile(SAS_PK.KEYFILE, false, null);

                            case 1 -> // gen keyfile, use pass
                                    SAS_PK.KEY = SAS_PK.generateKeyFile(SAS_PK.KEYFILE, true, SAS_PK.PASSWORD);

                            case 2 -> // sel keyfile, no pass
                                    SAS_PK.KEY = SAS_PK.extractKeyFile(SAS_PK.KEYFILE, null);

                            case 3 -> // sel keyfile, use pass
                                    SAS_PK.KEY = SAS_PK.extractKeyFile(SAS_PK.KEYFILE, SAS_PK.PASSWORD);

                            //case 4 -> // password only - keep key as null, derivation of key done in enc/dec methods
                        }

                    } catch (Exception e) {
                        switch (e.getMessage()) {
                            case "Keyfile Version Old" -> {
                                log("Failed to setup key. Keyfile supported by older PK versions.", true);
                                MainApp.logToLogWin("[!] Failed to setup key. Keyfile supported by older versions of PurpleKrypt.\n");
                            }
                            case "Keyfile Version Newer" -> {
                                log("Failed to setup key. Keyfile supported by newer versions.", true);
                                MainApp.logToLogWin("[!] Failed to setup key. Keyfile supported by newer PK versions of PurpleKrypt.\n");
                            }
                            case "Incorrect Password" -> {
                                log("Failed to setup key. Password either incorrect or not needed.", true);
                                MainApp.logToLogWin("[!] Failed to setup key. Password either incorrect or not needed.\n");
                            }
                            case "File Already Exists" -> {
                                log("Failed to generate key. Keyfile already exists", true);
                                MainApp.logToLogWin("[!] Failed to generate key. Keyfile already exists\n");
                            }
                            default -> {
                                log("Failed to setup key. Check Logs.", true);
                                MainApp.logToLogWin("[!] Failed to setup key\n"+e+"\n");
                            }
                        }
                        enable_confirm_process_button();
                        return;
                    }

                    long e1 = System.currentTimeMillis();
                    double d1 = (double) (e1 - s1) / 1000.0;

                    log("Key setup completed (in " + d1 + "s)", false);
                   MainApp.logToLogWin("[+] Key setup completed (in " + d1 + "s)\n");
                    key_extracted_icon.setVisible(true);

                    // Once key setup, no need for below data, so wipe
                    SAS_PK.clearMemory(true,(KEY_USAGE == 4));
                    UPDATE_KEY_ON_MEMORY = false;

                } else {
                   MainApp.logToLogWin("[?] Using key already in memory\n");
                }

                if (INPUT_TYPE == 0) { // text
                    processText();

                } else if (INPUT_TYPE == 1) { // files
                    processFiles();
                }
            }).start();
        } catch (Exception e) {
           MainApp.logToLogWin("[!] An unexpected error has occurred after clicking 'Process' button:\n"+ e + "\n");
           enable_confirm_process_button();
        }
    }

    private void processText() {
        String out = null;
        long s2 = System.currentTimeMillis();
        if (FUNCTION_TYPE == 0) {
            log("Encrypting...", false);

            if (KEY_USAGE == 4) { //password only
                out = SAS_PK.encryptString(SAS_PK.PASSWORD, input_text_input_field.getText(), null);
                if (out != null) {
                    output_text_output_field.setText(out);
                }
            } else {
                out = SAS_PK.encryptString(SAS_PK.KEY, input_text_input_field.getText(), null);
                if (out != null) {
                    output_text_output_field.setText(out);
                }
            }
        } else if (FUNCTION_TYPE == 1) {
            log("Decrypting...", false);
            if (KEY_USAGE == 4) { //password only
                out = SAS_PK.decryptString(SAS_PK.PASSWORD, input_text_input_field.getText(), null);
                if (out != null) {
                    output_text_output_field.setText(out);
                }
            } else {
                out = SAS_PK.decryptString(SAS_PK.KEY, input_text_input_field.getText(), null);
                if (out != null) {
                    output_text_output_field.setText(out);
                }
            }
        }
        long e2 = System.currentTimeMillis();
        double d2 = (double) (e2 - s2) / 1000.0;

        if (out != null) {
            log("Finished Processing Text (in " + d2 + "s)", false);
           MainApp.logToLogWin("[+] Finished Processing Text (in " + d2 + "s)\n");
        } else {
            log("Failed to Process Text (Check whether keyfile or password is correct)", true);
           MainApp.logToLogWin("[!] Failed to Process Text (Check whether keyfile or password is correct)\n");
        }
        enable_confirm_process_button();
    }

    private void processFiles() {

        // reset values
        MainApp.ALL_FILES_TO_PROCESS.clear();
        MainApp.ALL_DIR_TO_DELETE.clear();
        MainApp.FILES_PROCESSED = -1;

        if (FILES_TO_PROCESS.isEmpty()) {
            log("Add files to process",true);
            enable_confirm_process_button();
            return;
        }

        String outputDirPath = output_directory_file_input.getText();
        if (outputDirPath.isEmpty() && OUTPUT_METHOD != 2) {
            log("Provide an output directory",true);
            enable_confirm_process_button();
            return;
        }

        THREADS = SAS_PK.stringToInt(proc_sett_threads_input.getText());
        MainApp.THREADS_PER_FILE = SAS_PK.stringToInt(proc_sett_threads_per_file_input.getText());

        log("Scanning files...",false);
        MainApp.logToLogWin("[*] Scanning files...\n");
        MainApp.startLogWinQue();
        MainApp.FILES_PROCESSING_START = System.currentTimeMillis();

        for (DataFileInput_File value : FILES_TO_PROCESS.values()) {
            File file = new File(value.getPath());

            if (!file.exists()) {
                MainApp.logToLogWinQue("[!] " + file.getName() + " Not found. Continuing on...\n");
            }
            
            if (file.isDirectory()) {
                Queue<File> queue = new LinkedList<>();

                queue.add(file);
                if (OUTPUT_METHOD != 0) {
                    if (!MainApp.ALL_DIR_TO_DELETE.contains(file)) {
                        MainApp.ALL_DIR_TO_DELETE.add(file);
                    }
                }

                while (!queue.isEmpty()) {
                    File currentDirectory = queue.poll();

                    File[] files = currentDirectory.listFiles();
                    if (files != null) {
                        for (File eFile : files) {
                            if (eFile.isDirectory()) {
                                queue.add(eFile);
                                if (OUTPUT_METHOD != 0) {
                                    if (!MainApp.ALL_DIR_TO_DELETE.contains(eFile)) {
                                        MainApp.ALL_DIR_TO_DELETE.add(eFile);
                                    }
                                }
                            } else {
                                if (!MainApp.ALL_FILES_TO_PROCESS.contains(eFile)) {
                                    MainApp.ALL_FILES_TO_PROCESS.add(eFile);
                                    MainApp.logToLogWinQue("[+] " + eFile.getName() + " Added\n");
                                } else {
                                    MainApp.logToLogWinQue("[!] " + eFile.getName() + " Repeated file ignored.\n");
                                }
                            }
                        }
                    }
                }
            } else if (file.isFile()) {
                if (!MainApp.ALL_FILES_TO_PROCESS.contains(file)) {
                    MainApp.ALL_FILES_TO_PROCESS.add(file);
                    MainApp.logToLogWinQue("[+] " + file.getName() + " Added\n");
                } else {
                    MainApp.logToLogWinQue("[!] " + file.getName() + " Repeated file ignored.\n");
                }
            }
        }

        MainApp.startProcessingFiles();

    }



    // function (Custom Radio Button)
    @FXML
    protected void function_encrypt_button_onAction() {
        function_encrypt_button.getStyleClass().clear(); function_encrypt_button.getStyleClass().add("radio_button_rect_selected");
        function_decrypt_button.getStyleClass().clear(); function_decrypt_button.getStyleClass().add("radio_button_rect_unselected");

        key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_unselected");

        function_icon.setText("Enc");
        FUNCTION_TYPE = 0;
        
    }
    
    @FXML
    protected void function_decrypt_button_onAction() {
        function_encrypt_button.getStyleClass().clear(); function_encrypt_button.getStyleClass().add("radio_button_rect_unselected");
        function_decrypt_button.getStyleClass().clear(); function_decrypt_button.getStyleClass().add("radio_button_rect_selected");

        if (KEY_FILE_USAGE == 0) { //Generate
            select_key_button_onAction();
        }
        key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_disabled");

        function_icon.setText("Dec");
        FUNCTION_TYPE = 1;
        
    }



    // Key File Box Buttons
    @FXML
    protected void generate_key_button_onAction() {
        if (FUNCTION_TYPE == 0) {

            key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_selected");
            key_file_select_button.getStyleClass().clear(); key_file_select_button.getStyleClass().add("radio_button_rect_unselected");
            key_file_none_button.getStyleClass().clear(); key_file_none_button.getStyleClass().add("radio_button_rect_unselected");

            key_file_rect.setVisible(false);
            key_file_input_label.setText("Keyfile Save Path:");
            key_file_select_from_fs_button.setText("Set Path");
            key_file_select_from_fs_button.setVisible(true);


            KEY_FILE_USAGE = 0; //generate
            //main_next_button.setText("Generate");
        }
    }
    
    @FXML
    protected void select_key_button_onAction() {
        key_file_select_button.getStyleClass().clear(); key_file_select_button.getStyleClass().add("radio_button_rect_selected");
        if (FUNCTION_TYPE == 0) {
            key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_unselected");
        } else {
            key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_disabled");
        }
        key_file_none_button.getStyleClass().clear(); key_file_none_button.getStyleClass().add("radio_button_rect_unselected");

        key_file_rect.setVisible(false);
        key_file_input_label.setText("Keyfile Path:");
        key_file_select_from_fs_button.setText("Select Key");
        key_file_select_from_fs_button.setVisible(true);

        KEY_FILE_USAGE = 1; //select
        //main_next_button.setText("Extract");
    }

    @FXML
    protected void none_key_button_onAction() {
        key_file_generate_button.getStyleClass().clear(); key_file_generate_button.getStyleClass().add("radio_button_rect_unselected");
        key_file_select_button.getStyleClass().clear(); key_file_select_button.getStyleClass().add("radio_button_rect_unselected");
        key_file_none_button.getStyleClass().clear(); key_file_none_button.getStyleClass().add("radio_button_rect_selected");

        key_file_rect.setVisible(true);
        key_file_input_label.setText("No Keyfile");
        key_file_select_from_fs_button.setVisible(false);

        password_yes_button_onAction(); // set to use password

        KEY_FILE_USAGE = 2; //none
    }

    // Password File Box Buttons
    @FXML
    protected void password_yes_button_onAction() {
            password_yes_button.getStyleClass().clear(); password_yes_button.getStyleClass().add("radio_button_rect_selected");
            password_no_button.getStyleClass().clear(); password_no_button.getStyleClass().add("radio_button_rect_unselected");

            password_rect.setVisible(false);
            
            USE_PASSWORD = true; 
        
    }

    @FXML
    protected void password_no_button_onAction() {
        password_yes_button.getStyleClass().clear(); password_yes_button.getStyleClass().add("radio_button_rect_unselected");
        password_no_button.getStyleClass().clear(); password_no_button.getStyleClass().add("radio_button_rect_selected");

        password_rect.setVisible(true);

        if (KEY_FILE_USAGE == 2) { // if no key file used, then set to generate
            generate_key_button_onAction();
        }

        USE_PASSWORD = false;
    }

    // ---------- SELECT KEY BOX UI ----------
    @FXML
    protected void key_file_select_from_fs_button_onAction() {
        //select_key_button_onAction();
        FileChooser fileChooser = new FileChooser();
        if (LAST_VISITED_DIR != null) {
            fileChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        if (KEY_FILE_USAGE == 0) {

            fileChooser.setTitle("Save Keyfile");
            FileChooser.ExtensionFilter extensionFilter = new FileChooser.ExtensionFilter("PurpleKrypt Keyfile (*.pkk)", "*.pkk");
            fileChooser.getExtensionFilters().add(extensionFilter);
            fileChooser.setInitialFileName("untitled.pkk");
            Stage stage = (Stage) root.getScene().getWindow();

            File selectedFile = fileChooser.showSaveDialog(stage);

            if (selectedFile != null) {
                key_file_input.setText(selectedFile.getAbsolutePath());
                LAST_VISITED_DIR = selectedFile.getParentFile();
            }

        } else if (KEY_FILE_USAGE == 1) {
            fileChooser.setTitle("Select Keyfile");
            Stage stage = (Stage) root.getScene().getWindow();
            FileChooser.ExtensionFilter extensionFilter = new FileChooser.ExtensionFilter("PurpleKrypt Keyfile (*.pkk)", "*.pkk");
            fileChooser.getExtensionFilters().add(extensionFilter);

            File selectedFile = fileChooser.showOpenDialog(stage);

            if (selectedFile != null) {
                key_file_input.setText(selectedFile.getAbsolutePath());
                LAST_VISITED_DIR = selectedFile.getParentFile();
            }
        }
    }

    // Select Key File Drag and Drop
    @FXML
    private void select_key_file_onDragOver(DragEvent event) {
        if (event.getGestureSource() != key_file_input && event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files.size() == 1 && files.get(0).getName().toLowerCase().endsWith(".pkk")) {
                event.acceptTransferModes(TransferMode.COPY);
                key_file_box.getStyleClass().clear(); key_file_box.getStyleClass().add("layer1_box_selected");
                key_file_box_header.getStyleClass().clear(); key_file_box_header.getStyleClass().add("layer1_box_header_background_selected");
            }
        }
        event.consume();
    }

    @FXML
    private void select_key_file_onDragDropped(DragEvent event) {

        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            select_key_button_onAction();
            success = true;
            List<File> files = db.getFiles();
            if (files.size() == 1 && files.get(0).getName().toLowerCase().endsWith(".pkk")) {
                key_file_input.setText(files.get(0).getAbsolutePath());
                select_key_button_onAction();
            }
        }
        event.setDropCompleted(success);
        event.consume();
    }

    @FXML
    private void select_key_file_onDragExited(DragEvent event) {
        key_file_box.getStyleClass().clear(); key_file_box.getStyleClass().add("layer1_box");
        key_file_box_header.getStyleClass().clear(); key_file_box_header.getStyleClass().add("layer1_box_header_background");
    }


    // ---------- PASSWORD BOX UI ----------
    @FXML
    protected void password_input_visibility_button_onAction() {
        if (PASSWORD_IS_VISIBLE) {
            PASSWORD_IS_VISIBLE = false;
            password_input_visibility_button.setText("Show");

            password_input.setText(password_input_text.getText());

            password_input.setVisible(true);
            password_input_text.setVisible(false);
        } else {
            PASSWORD_IS_VISIBLE = true;
            password_input_visibility_button.setText("Hide");

            password_input_text.setText(password_input.getText());

            password_input.setVisible(false);
            password_input_text.setVisible(true);
        }
    }

    private String getPassword() {
        if (PASSWORD_IS_VISIBLE) {
            return password_input_text.getText();
        } else {
            return password_input.getText();
        }
    }

    // ---------- DATA TAB UI ----------
    // input data type (Custom Radio Button)
    @FXML
    protected void input_type_text_button_onAction() {
        input_type_text.getStyleClass().clear(); input_type_text.getStyleClass().add("radio_button_rect_selected");
        input_type_file.getStyleClass().clear(); input_type_file.getStyleClass().add("radio_button_rect_unselected");

        input_file_box.setVisible(false);
        output_file_box.setVisible(false);
        input_text_box.setVisible(true);
        output_text_box.setVisible(true);
        paste_to_clipboard_button.setVisible(true);

        INPUT_TYPE = 0;
        
    }
    
    @FXML
    protected void input_type_file_button_onAction() {
        input_type_text.getStyleClass().clear(); input_type_text.getStyleClass().add("radio_button_rect_unselected");
        input_type_file.getStyleClass().clear(); input_type_file.getStyleClass().add("radio_button_rect_selected");

        input_text_box.setVisible(false);
        output_text_box.setVisible(false);
        input_file_box.setVisible(true);
        output_file_box.setVisible(true);
        paste_to_clipboard_button.setVisible(false);

        INPUT_TYPE = 1;
    }

    // Input Text Buttons
    @FXML
    protected void copy_to_clipboard_button_onAction() {
        if (!output_text_output_field.getText().isEmpty()) {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(output_text_output_field.getText());
            clipboard.setContent(content);
            log("Copied to Clipboard",false);
        }
    }

    @FXML
    protected void paste_to_clipboard_button_onAction() {
        Clipboard clipboard = Clipboard.getSystemClipboard();
        if (clipboard.hasString()) {
            input_text_input_field.setText(clipboard.getString());
        }
    }

    // Input File buttons
    @FXML
    protected void input_file_add_button_onAction() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File To Process");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            fileChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            if (selectedFile.isFile()) {
                String ID = "" + FILES_TO_PROCESS.size();
                FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "FILE", selectedFile.getName(), selectedFile.getAbsolutePath()));
                LAST_VISITED_DIR = selectedFile.getParentFile();
                COMMON_PATH = selectedFile.getParentFile().getAbsolutePath();
                set_process_file_data();
            }
        }
    }

    @FXML
    protected void input_dir_add_button_onAction() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Directory/Folder To Process");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            directoryChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            if (selectedDirectory.isDirectory()) {
                String ID = "" + FILES_TO_PROCESS.size();
                FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "DIR", selectedDirectory.getName(), selectedDirectory.getAbsolutePath()));
                LAST_VISITED_DIR = selectedDirectory.getParentFile();
                COMMON_PATH = selectedDirectory.getParentFile().getAbsolutePath();
                set_process_file_data();
            }
        }
    }

    @FXML
    protected void input_file_remove_button_onAction() {
        //remove file path from list based on the selected row in table
        if (FILES_TO_PROCESS.containsKey(ID_OF_SELECTED_DATA_FILE)) {
            FILES_TO_PROCESS.remove(ID_OF_SELECTED_DATA_FILE);
            set_process_file_data();
            input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("disabled_button");
        }
    }

    private void set_process_file_data() {
        new Thread( () -> {
            ObservableList<DataFileInput_File> dataFileInput_files = FXCollections.observableArrayList();

            for(Map.Entry<String, DataFileInput_File> entry : FILES_TO_PROCESS.entrySet()) {
                DataFileInput_File dif = entry.getValue();
                dataFileInput_files.add(dif);
            }

            input_file_table.setItems(dataFileInput_files);

        }).start();
    }

    // Input File Drag and Drop
    @FXML
    private void input_file_onDragOver(DragEvent event) {
        if (event.getGestureSource() != input_file_table && event.getDragboard().hasFiles()) {
            event.acceptTransferModes(TransferMode.COPY);
            input_data_box.getStyleClass().clear(); input_data_box.getStyleClass().add("layer1_box_selected");
            input_data_box_header.getStyleClass().clear(); input_data_box_header.getStyleClass().add("layer1_box_header_background_selected");
        }
        event.consume();
    }

    @FXML
    private void input_file_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            COMMON_PATH = files.get(0).getParentFile().getAbsolutePath();
            
            for (File eFile: files) {
                if (eFile.isFile()) {
                    String ID = "" + FILES_TO_PROCESS.size();
                    FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "FILE", eFile.getName(), eFile.getAbsolutePath()));
                } else if (eFile.isDirectory()) {
                    String ID = "" + FILES_TO_PROCESS.size();
                    FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "DIR", eFile.getName(), eFile.getAbsolutePath()));
                }
            }
            set_process_file_data();
        }
        event.setDropCompleted(success);
        event.consume();
    }

    @FXML
    private void input_file_onDragExited(DragEvent event) {
        input_data_box.getStyleClass().clear(); input_data_box.getStyleClass().add("layer1_box");
        input_data_box_header.getStyleClass().clear(); input_data_box_header.getStyleClass().add("layer1_box_header_background");
    }


    // Output directory select
    // Key File Box Buttons
    @FXML
    protected void output_copy_button_onAction() {
            output_copy_button.getStyleClass().clear(); output_copy_button.getStyleClass().add("radio_button_rect_selected");
            output_move_button.getStyleClass().clear(); output_move_button.getStyleClass().add("radio_button_rect_unselected");
            output_replace_button.getStyleClass().clear(); output_replace_button.getStyleClass().add("radio_button_rect_unselected");

            output_method_rect.setVisible(false);


            OUTPUT_METHOD = 0; //copy
    }

    @FXML
    protected void output_move_button_onAction() {
        output_copy_button.getStyleClass().clear(); output_copy_button.getStyleClass().add("radio_button_rect_unselected");
        output_move_button.getStyleClass().clear(); output_move_button.getStyleClass().add("radio_button_rect_selected");
        output_replace_button.getStyleClass().clear(); output_replace_button.getStyleClass().add("radio_button_rect_unselected");

        output_method_rect.setVisible(false);


        OUTPUT_METHOD = 1; //move
    }

    @FXML
    protected void output_replace_button_onAction() {
        output_copy_button.getStyleClass().clear(); output_copy_button.getStyleClass().add("radio_button_rect_unselected");
        output_move_button.getStyleClass().clear(); output_move_button.getStyleClass().add("radio_button_rect_unselected");
        output_replace_button.getStyleClass().clear(); output_replace_button.getStyleClass().add("radio_button_rect_selected");

        output_method_rect.setVisible(true);


        OUTPUT_METHOD = 2; //replace
    }
    @FXML
    protected void output_directory_select_button_onAction() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Output Directory/Folder");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            directoryChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            if (selectedDirectory.isDirectory()) {
                output_directory_file_input.setText(selectedDirectory.getAbsolutePath());
                OUTPUT_DIR = selectedDirectory.getAbsolutePath();
                LAST_VISITED_DIR = selectedDirectory.getParentFile();
            }
        }
    }

    // Output Directory Drag and Drop
    @FXML
    private void output_directory_path_onDragOver(DragEvent event) {
        if (event.getGestureSource() != key_file_input && event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files.size() == 1 && files.get(0).isDirectory()) {
                event.acceptTransferModes(TransferMode.COPY);
                output_dir_box.getStyleClass().clear(); output_dir_box.getStyleClass().add("layer1_box_selected");
                output_dir_box_header.getStyleClass().clear(); output_dir_box_header.getStyleClass().add("layer1_box_header_background_selected");
            }
        }
        event.consume();
    }

    @FXML
    private void output_directory_path_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            if (files.size() == 1 && files.get(0).isDirectory()) {
                output_directory_file_input.setText(files.get(0).getAbsolutePath());
                OUTPUT_DIR = files.get(0).getAbsolutePath();
            }
        }
        event.setDropCompleted(success);
        event.consume();
    }

    @FXML
    private void output_directory_path_onDragExited(DragEvent event) {
        output_dir_box.getStyleClass().clear(); output_dir_box.getStyleClass().add("layer1_box");
        output_dir_box_header.getStyleClass().clear(); output_dir_box_header.getStyleClass().add("layer1_box_header_background");
    }

    // Use PK AAD ID
    @FXML
    protected void use_pk_aad_id_checkbox_onAction() {
        if (USE_PK_AAD_ID) {
            USE_PK_AAD_ID = false;
            use_pk_aad_id_checkbox.getStyleClass().clear(); use_pk_aad_id_checkbox.getStyleClass().add("check_box_unselected");
            clearLogCondition("Note: Data cannot be decrypted if you lose 'pk_aad_id' file. Use at own risk.");
        } else {
            USE_PK_AAD_ID = true;
            use_pk_aad_id_checkbox.getStyleClass().clear(); use_pk_aad_id_checkbox.getStyleClass().add("check_box_selected");
            log("Note: Data cannot be decrypted if you lose 'pk_aad_id' file. Use at own risk.",false);
        }
    }

    // Encrypt file names
    @FXML
    protected void random_file_names_checkbox_onAction() {
        if (RANDOM_FILE_NAMES) {
            RANDOM_FILE_NAMES = false;
            random_file_names_checkbox.getStyleClass().clear(); random_file_names_checkbox.getStyleClass().add("check_box_unselected");
        } else {
            RANDOM_FILE_NAMES = true;
            random_file_names_checkbox.getStyleClass().clear(); random_file_names_checkbox.getStyleClass().add("check_box_selected");
        }
    }


    // Logging to Main UI
    private static ScheduledExecutorService skipLogSchedule;
    private static String skipLog = "";
    private static boolean skipLogIsError = false;
    private static boolean updateSkipLog = false;

    protected static synchronized void log(String msg, boolean isError) {
        if (isError) {
            msg_text_STATIC.setFill(Color.web("#e43737"));
        } else {
            msg_text_STATIC.setFill(Color.web("#aaaaaa"));
        }
        msg_text_STATIC.setText(msg);
    }

    protected static void clearLog() {
        msg_text_STATIC.setText("");
    }

    protected static void clearLogCondition(String equalsString) {
        if (msg_text_STATIC.getText().equals(equalsString)) {
            msg_text_STATIC.setText("");
        }
    }

    // skip log system allows to
    protected static void startSkipLog() {
        skipLogSchedule = Executors.newScheduledThreadPool(1);
        skipLogSchedule.scheduleAtFixedRate(() -> {
            if (updateSkipLog) {
                if (skipLogIsError) {
                    msg_text_STATIC.setFill(Color.web("#e43737"));
                } else {
                    msg_text_STATIC.setFill(Color.web("#aaaaaa"));
                }
                msg_text_STATIC.setText(skipLog);
                updateSkipLog = false;
            }
        },0,MainApp.LOG_INTERVAL, TimeUnit.MILLISECONDS);
    }

    protected static void stopSkipLog() {
        if (updateSkipLog) {
            if (skipLogIsError) {
                msg_text_STATIC.setFill(Color.web("#e43737"));
            } else {
                msg_text_STATIC.setFill(Color.web("#aaaaaa"));
            }
            msg_text_STATIC.setText(skipLog);
            updateSkipLog = false;
        }
        skipLogSchedule.shutdown();
    }

    protected static synchronized void logToSkipLog(String log, boolean isError) {
        skipLogIsError = isError;
        skipLog = log;
        updateSkipLog = true;
    }

}

