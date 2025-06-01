import sqlite3
import csv
import hashlib
from tkinter import *
from tkinter import ttk, messagebox, filedialog
import datetime
from tkcalendar import DateEntry
current_user = None  

# Basic Setup
def setup_database():
    conn = sqlite3.connect('customer_data.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        name TEXT,
        gender TEXT,
        patient_id TEXT PRIMARY KEY,
        address TEXT,
        doctor_name TEXT,
        fees REAL,
        ward TEXT,
        mob_no TEXT,
        date TEXT,
        co_patient TEXT
    )
''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    cursor.execute('SELECT * FROM users WHERE user_id = ?', ('admin',))
    if not cursor.fetchone():
        default_pass = hash_password('password123')
        cursor.execute('INSERT INTO users (user_id, password) VALUES (?, ?)', ('admin', default_pass))
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Login Screen
def show_login_screen():
    for widget in root.winfo_children():
        widget.destroy()
    root.unbind('<Return>')

    ttk.Label(root, text="Login", font=("Arial", 20)).pack(pady=20)

    global user_id_entry, password_entry, show_password_var

    ttk.Label(root, text="User ID:", font=("Arial", 12)).pack(pady=5)
    user_id_entry = ttk.Entry(root, width=25)
    user_id_entry.pack(pady=5)

    ttk.Label(root, text="Password:", font=("Arial", 12)).pack(pady=5)
    password_entry = ttk.Entry(root, show="*", width=25)
    password_entry.pack(pady=5)

    show_password_var = BooleanVar()
    show_password_check = Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
    show_password_check.pack(pady=5)

    ttk.Button(root, text="Login", command=authenticate_user).pack(pady=10)
    ttk.Button(root, text="Register", command=register_user).pack(pady=5)

    root.bind('<Return>', lambda event: authenticate_user())

def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def authenticate_user():
    global current_user
    user_id = user_id_entry.get()
    password = password_entry.get()
    hashed_password = hash_password(password)

    conn = sqlite3.connect('customer_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ? AND password = ?', (user_id, hashed_password))
    result = cursor.fetchone()
    conn.close()

    if result:
        current_user = user_id
        messagebox.showinfo("Success", "Login successful!")
        show_main_interface()
    else:
        messagebox.showerror("Error", "Invalid User ID or Password!")

def register_user():
    user_id = user_id_entry.get()
    password = password_entry.get()

    if not user_id or not password:
        messagebox.showerror("Error", "Please fill in both fields!")
        return

    hashed_password = hash_password(password)
    conn = sqlite3.connect('customer_data.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (user_id, password) VALUES (?, ?)', (user_id, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "User ID already exists!")
    finally:
        conn.close()

def create_nav_bar():
    nav_frame = ttk.Frame(root)
    nav_frame.grid(row=0, column=0, columnspan=4, sticky="ew")

    ttk.Button(nav_frame, text="Enter Data", command=show_enter_data_interface).pack(side="left", padx=10, pady=5)
    ttk.Button(nav_frame, text="Get Data", command=show_get_data_interface).pack(side="left", padx=10, pady=5)
    ttk.Button(nav_frame, text="Dashboard", command=show_dashboard).pack(side="left", padx=10, pady=5)

    if current_user == "admin":
        ttk.Button(nav_frame, text="Manage Users", command=show_manage_users_interface).pack(side="left", padx=10, pady=5)

    ttk.Button(nav_frame, text="Import CSV", command=import_from_csv).pack(side="left", padx=10, pady=5)

    ttk.Button(nav_frame, text="Logout", command=logout_user).pack(side="right", padx=10, pady=5)
    ttk.Button(nav_frame, text="Exit", command=root.quit).pack(side="right", padx=10, pady=5)

    ttk.Separator(root, orient="horizontal").grid(row=1, column=0, columnspan=4, sticky="ew", pady=5)

def logout_user():
    global current_user
    current_user = None
    for widget in root.winfo_children():
        widget.destroy()
    root.unbind('<Return>')
    show_login_screen()

def show_dashboard():
    for widget in root.winfo_children()[1:]:
        widget.destroy()

    ttk.Label(root, text="Dashboard", font=("Arial", 18)).grid(row=2, column=0, columnspan=4, pady=20)

    filter_frame = ttk.Frame(root)
    filter_frame.grid(row=3, column=0, columnspan=4, pady=10, padx=20)

    ttk.Label(filter_frame, text="Ward:").grid(row=0, column=0, padx=10, sticky="w")
    ward_filter = ttk.Combobox(filter_frame, width=12, state="readonly")
    ward_filter.grid(row=0, column=1, padx=10, pady=5)

    conn = sqlite3.connect("customer_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT ward FROM patients")
    wards = [row[0] for row in cursor.fetchall()]
    conn.close()

    ward_filter['values'] = ["All"] + wards
    ward_filter.current(0)

    ttk.Label(filter_frame, text="Gender:").grid(row=0, column=2, padx=10, sticky="w")
    gender_filter = ttk.Combobox(filter_frame, width=12, state="readonly")
    gender_filter.grid(row=0, column=3, padx=10, pady=5)
    gender_filter['values'] = ["All", "Male", "Female", "Other"]
    gender_filter.current(0)

    ttk.Label(filter_frame, text="Doctor:").grid(row=1, column=0, padx=10, sticky="w")
    doctor_filter = ttk.Combobox(filter_frame, width=12, state="readonly")
    doctor_filter.grid(row=1, column=1, padx=10, pady=5)

    conn = sqlite3.connect("customer_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT doctor_name FROM patients")
    doctors = [row[0] for row in cursor.fetchall()]
    conn.close()

    doctor_filter['values'] = ["All"] + doctors
    doctor_filter.current(0)

    ttk.Label(filter_frame, text="From Date:").grid(row=1, column=2, padx=10, sticky="w")
    from_date_filter = DateEntry(filter_frame, width=12, date_pattern="yyyy-mm-dd")
    from_date_filter.grid(row=1, column=3, padx=10, pady=5)

    ttk.Label(filter_frame, text="To Date:").grid(row=1, column=4, padx=10, sticky="w")
    to_date_filter = DateEntry(filter_frame, width=12, date_pattern="yyyy-mm-dd")
    to_date_filter.grid(row=1, column=5, padx=10, pady=5)

    def apply_dashboard_filters():
        conn = sqlite3.connect("customer_data.db")
        cursor = conn.cursor()

        query = "SELECT COUNT(*), COUNT(DISTINCT ward), SUM(fees) FROM patients WHERE 1=1"
        params = []

        if ward_filter.get() != "All":
            query += " AND ward = ?"
            params.append(ward_filter.get())

        if gender_filter.get() != "All":
            query += " AND gender = ?"
            params.append(gender_filter.get())

        if doctor_filter.get() != "All":
            query += " AND doctor_name = ?"
            params.append(doctor_filter.get())

        if from_date_filter.get():
            query += " AND date >= ?"
            params.append(from_date_filter.get())

        if to_date_filter.get():
            query += " AND date <= ?"
            params.append(to_date_filter.get())

        cursor.execute(query, params)
        result = cursor.fetchone()
        total_patients = result[0] if result[0] else 0
        total_wards = result[1] if result[1] else 0
        total_fees = result[2] if result[2] else 0
        conn.close()

        total_fees = total_fees or 0
        for i, (_, value) in enumerate([
            ("Total Patients", total_patients),
            ("Total Wards", total_wards),
            ("Total Fees", f"₹{total_fees:.2f}")
        ]):
            stats_labels[i].config(text=value)

    def reset_filters():
        ward_filter.current(0)
        gender_filter.current(0)
        doctor_filter.current(0)
        from_date_filter.set_date(datetime.date.today())
        to_date_filter.set_date(datetime.date.today())
        apply_dashboard_filters()

    ttk.Button(filter_frame, text="Filter", command=apply_dashboard_filters).grid(row=1, column=6, padx=10, pady=5)
    ttk.Button(filter_frame, text="Reset", command=reset_filters).grid(row=1, column=7, padx=10, pady=5)

    conn = sqlite3.connect("customer_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT ward) FROM patients")
    total_wards = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(fees) FROM patients")
    total_fees = cursor.fetchone()[0] or 0
    conn.close()

    stats = [
        ("Total Patients", total_patients),
        ("Total Wards", total_wards),
        ("Total Fees", f"₹{total_fees:.2f}")
    ]

    global stats_labels
    stats_labels = []

    stats_frame = ttk.Frame(root)
    stats_frame.grid(row=4, column=0, columnspan=4, pady=20)

    for i, (label, value) in enumerate(stats):
        ttk.Label(stats_frame, text=label + ":", font=("Arial", 14)).grid(row=i, column=0, padx=20, pady=5, sticky="w")
        lbl = ttk.Label(stats_frame, text=value, font=("Arial", 14))
        lbl.grid(row=i, column=1, padx=20, pady=5, sticky="w")
        stats_labels.append(lbl)

def show_main_interface():
    for widget in root.winfo_children():
        widget.destroy()
    root.unbind('<Return>')
    create_nav_bar()
    show_enter_data_interface()

def show_enter_data_interface():
    for widget in root.winfo_children()[1:]:
        widget.destroy()

    ttk.Label(root, text="Enter Patient Data", font=("Arial", 18)).grid(row=2, column=0, columnspan=4, pady=20)

    form_frame = ttk.Frame(root)
    form_frame.grid(row=3, column=0, columnspan=4, pady=10)

    labels = ["Patient Name", "Gender", "Patient ID", "Address", "Doctor Name", "Fees", "Ward", "Mobile No", "Date", "Co-Patient"]
    global entries
    entries = {}

    for i, label in enumerate(labels):
        ttk.Label(form_frame, text=label + ":").grid(row=i, column=0, sticky=W, padx=10, pady=5)
        if label == "Gender":
            gender_var = StringVar(value="")

            gender_frame = ttk.Frame(form_frame)
            gender_frame.grid(row=i, column=1, columnspan=3, sticky=W, padx=10, pady=5)

            ttk.Radiobutton(gender_frame, text="Male", variable=gender_var, value="Male").pack(side=LEFT, padx=5)
            ttk.Radiobutton(gender_frame, text="Female", variable=gender_var, value="Female").pack(side=LEFT, padx=5)
            ttk.Radiobutton(gender_frame, text="Other", variable=gender_var, value="Other").pack(side=LEFT, padx=5)

            entries[label] = gender_var

        else:
            entry = ttk.Entry(form_frame, width=30)
            entry.grid(row=i, column=1, padx=10, pady=5)
            entries[label] = entry

    def submit_data():
        values = [entries[label].get() for label in labels]
        # Using radio buttons
        selected_gender = gender_var.get()
        values[1] = selected_gender  

        if any(not v.strip() for v in values):
            messagebox.showerror("Error", "All fields are required!")
            return

        if len(values) != 10:
            messagebox.showerror("Error", f"Expected 10 fields, got {len(values)}. Please check all inputs.")
            return

        try:
            conn = sqlite3.connect('customer_data.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', values)
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Patient data saved successfully!")
            show_enter_data_interface()
        except sqlite3.IntegrityError as e:
            messagebox.showerror("Error", f"Patient ID already exists!\n{e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

    
    ttk.Button(form_frame, text="Submit", command=submit_data).grid(row=len(labels), column=0, columnspan=2, pady=10)

def show_get_data_interface():
    for widget in root.winfo_children()[1:]:
        widget.destroy()

    ttk.Label(root, text="Patient Records", font=("Arial", 16)).grid(row=2, column=0, columnspan=4, pady=10)

    search_var = StringVar()
    search_entry = ttk.Entry(root, textvariable=search_var, width=30)
    search_entry.grid(row=3, column=0, padx=10)
    ttk.Button(root, text="Search", command=lambda: load_data(search_var.get(), start_date_var.get(), end_date_var.get())).grid(row=3, column=1, padx=5)

    start_date_var = StringVar()
    end_date_var = StringVar()
    ttk.Label(root, text="Start Date (YYYY-MM-DD):").grid(row=3, column=2, padx=5)
    start_date_entry = ttk.Entry(root, textvariable=start_date_var, width=15)
    start_date_entry.grid(row=3, column=3, padx=5)

    ttk.Label(root, text="End Date (YYYY-MM-DD):").grid(row=3, column=4, padx=5)
    end_date_entry = ttk.Entry(root, textvariable=end_date_var, width=15)
    end_date_entry.grid(row=3, column=5, padx=5)

    columns = ["name", "gender", "patient_id", "address", "doctor_name", "fees", "ward", "mob_no", "date", "co_patient"]
    tree = ttk.Treeview(root, columns=columns, show="headings")

    for col in columns:
        tree.heading(col, text=col.replace("_", " ").title())
        tree.column(col, width=130)

    tree.grid(row=4, column=0, columnspan=6, padx=20, pady=10, sticky="nsew")

    scrollbar = Scrollbar(root, orient=VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=4, column=6, sticky='ns')

    def load_data(keyword="", start_date="", end_date=""):
        for row in tree.get_children():
            tree.delete(row)
        conn = sqlite3.connect('customer_data.db')
        cursor = conn.cursor()
        query = 'SELECT name, gender, patient_id, address, doctor_name, fees, ward, mob_no, date, co_patient FROM patients'
        conditions = []
        params = []

        if keyword:
            keyword = f"%{keyword}%"
            conditions.append('(name LIKE ? OR patient_id LIKE ? OR doctor_name LIKE ? OR ward LIKE ? OR fees LIKE ?)')
            params.extend([keyword] * 5)

        if start_date:
            conditions.append('date >= ?')
            params.append(start_date)

        if end_date:
            conditions.append('date <= ?')
            params.append(end_date)

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        for row in cursor.fetchall():
            tree.insert("", END, values=row)
        conn.close()

    def delete_selected():
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Select Record", "Please select a record to delete.")
            return
        patient_id = tree.item(selected[0])['values'][2]  # Ensure the correct column index for patient_id
        confirm = messagebox.askyesno("Confirm Delete", f"Delete patient record '{patient_id}'?")
        if confirm:
            try:
                conn = sqlite3.connect('customer_data.db')
                cursor = conn.cursor()
                cursor.execute('DELETE FROM patients WHERE patient_id = ?', (patient_id,))
                conn.commit()
                conn.close()
                load_data()  # Reload the data to reflect the deletion
                messagebox.showinfo("Deleted", f"Patient record '{patient_id}' deleted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while deleting: {e}")


    def edit_selected():
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Select Record", "Please select a record to edit.")
            return
        values = tree.item(selected[0])['values']

        edit_win = Toplevel(root)
        edit_win.title("Edit Record")
        edit_entries = {}
        for idx, col in enumerate(columns):
            Label(edit_win, text=col.replace("_", " ").title() + ":").grid(row=idx, column=0, padx=10, pady=5, sticky=W)
            entry = Entry(edit_win, width=40)
            entry.insert(0, values[idx])
            entry.grid(row=idx, column=1, padx=10, pady=5)
            edit_entries[col] = entry

        def save_edited():
            updated_values = [edit_entries[col].get() for col in columns]
            try:
                conn = sqlite3.connect('customer_data.db')
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE patients SET
                        name=?, gender=?, address=?, doctor_name=?, fees=?, ward=?, mob_no=?, date=?, co_patient=?
                    WHERE patient_id=?
                ''', (
                    updated_values[0], updated_values[1], updated_values[3], updated_values[4],
                    updated_values[5], updated_values[6], updated_values[7], updated_values[8],
                    updated_values[9], updated_values[2]
                ))
                conn.commit()
                conn.close()
                edit_win.destroy()
                load_data()
                messagebox.showinfo("Updated", f"Record '{updated_values[2]}' updated successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Update failed:\n{e}")

        Button(edit_win, text="Save Changes", command=save_edited).grid(row=len(columns), column=0, columnspan=2, pady=10)


        

    def export_to_csv():
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[["CSV Files", "*.csv"]])
        if not file_path:
            return
        with open(file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(columns)
            for row_id in tree.get_children():
                row = tree.item(row_id)['values']
                writer.writerow(row)
        messagebox.showinfo("Exported", f"Data exported to {file_path}")

    ttk.Button(root, text="Delete Selected Record", command=delete_selected).grid(row=5, column=0, pady=10)
    ttk.Button(root, text="Edit Selected Record", command=edit_selected).grid(row=5, column=1, pady=10)
    ttk.Button(root, text="Export to CSV", command=export_to_csv).grid(row=5, column=2, pady=10)
    load_data()

def show_manage_users_interface(): 
    for widget in root.winfo_children()[1:]:
        widget.destroy()

    ttk.Label(root, text="Manage Users", font=("Arial", 16)).grid(row=2, column=0, columnspan=4, pady=10)
    ttk.Label(root, text="View and Manage User Accounts").grid(row=3, column=0, columnspan=4)

    
    columns = ("User ID", "Password (Hashed)")  
    user_tree = ttk.Treeview(root, columns=columns, show="headings", height=10)
    for col in columns:
        user_tree.heading(col, text=col)
        user_tree.column(col, width=200)
    user_tree.grid(row=4, column=0, columnspan=4, padx=10, pady=10)
    

    # Edit User
    def edit_user():
        selected = user_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a user to edit.")
            return
        values = user_tree.item(selected[0])['values']
        user_id = values[0]  

        edit_win = Toplevel(root)
        edit_win.title("Edit User")

        labels = ["Username", "Email"]
        fields = {}
        for i, label in enumerate(labels):
            Label(edit_win, text=label + ":").grid(row=i, column=0, padx=10, pady=5, sticky=W)
            entry = Entry(edit_win, width=40)
            entry.insert(0, values[i + 1])  
            entry.grid(row=i, column=1, padx=10, pady=5)
            fields[label.lower()] = entry

        def save_user_changes():
            new_username = fields["username"].get()
            new_email = fields["email"].get()

            conn = sqlite3.connect('customer_data.db')
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET username = ?, email = ? WHERE user_id = ?  # Make sure the column is correct
            """, (new_username, new_email, user_id))
            conn.commit()
            conn.close()
            edit_win.destroy()
            load_users()
            messagebox.showinfo("Updated", "User updated successfully.")

        Button(edit_win, text="Save Changes", command=save_user_changes).grid(row=3, column=0, columnspan=2, pady=10)

    
    def delete_user():
        selected = user_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a user to delete.")
            return
        values = user_tree.item(selected[0])['values']
        user_id = values[0]
        confirm = messagebox.askyesno("Confirm Delete", f"Delete user ID {user_id}?")
        if confirm:
            conn = sqlite3.connect('customer_data.db')
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))  # Correct column name
            conn.commit()
            conn.close()
            load_users()
            messagebox.showinfo("Deleted", "User deleted successfully.")

    
    def load_users():
        for row in user_tree.get_children():
            user_tree.delete(row)

        conn = sqlite3.connect("customer_data.db")
        cursor = conn.cursor()

        
        cursor.execute("SELECT user_id, password FROM users")  
        rows = cursor.fetchall()

        if not rows:
            print("No users found!")
        else:
            for row in rows:
                print(f"Inserting row: {row}")  
                user_tree.insert("", END, values=row)
    
        conn.close()

    
    ttk.Button(root, text="Edit Selected", command=edit_user).grid(row=5, column=1, pady=10)
    ttk.Button(root, text="Delete Selected", command=delete_user).grid(row=5, column=2, pady=10)

    
    load_users()





    
    ttk.Button(root, text="Edit Selected", command=edit_user).grid(row=5, column=1, pady=10)
    ttk.Button(root, text="Delete Selected", command=delete_user).grid(row=5, column=2, pady=10)

    
    load_users()


def import_from_csv():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            rows = list(reader)

        conn = sqlite3.connect('customer_data.db')
        cursor = conn.cursor()

        for row in rows[1:]:  
            cursor.execute('''
                INSERT INTO patients (name, gender, patient_id, address, doctor_name, fees, ward, mob_no, date, co_patient)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', row)

        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Data imported successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while importing data:\n{e}")


if __name__ == "__main__":
    root = Tk()
    root.title("Patient Data Management System")
    root.state('zoomed')  

    setup_database()
    show_login_screen()
    root.mainloop()
