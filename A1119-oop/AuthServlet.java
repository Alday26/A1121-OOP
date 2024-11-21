import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.MessageDigest;
import java.util.Base64;

public class AuthServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/authdb";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "";

    // Hash password for secure storage
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return null;
        }
    }

    // Login Servlet
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String action = request.getParameter("action");
        
        if ("login".equals(action)) {
            String email = request.getParameter("email");
            String password = hashPassword(request.getParameter("password"));
            
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
                String query = "SELECT * FROM users WHERE email = ? AND password = ?";
                PreparedStatement pstmt = conn.prepareStatement(query);
                pstmt.setString(1, email);
                pstmt.setString(2, password);
                
                ResultSet rs = pstmt.executeQuery();
                
                if (rs.next()) {
                    // Successful login
                    HttpSession session = request.getSession();
                    session.setAttribute("user", email);
                    response.sendRedirect("dashboard.jsp");
                } else {
                    // Failed login
                    response.sendRedirect("index.jsp?error=invalid");
                }
            } catch (SQLException e) {
                e.printStackTrace();
                response.sendRedirect("index.jsp?error=database");
            }
        } 
        // Signup Logic
        else if ("signup".equals(action)) {
            String fullName = request.getParameter("fullName");
            String email = request.getParameter("email");
            String password = hashPassword(request.getParameter("password"));
            String confirmPassword = hashPassword(request.getParameter("confirmPassword"));
            
            // Basic validation
            if (!password.equals(confirmPassword)) {
                response.sendRedirect("index.jsp?error=passwordmismatch");
                return;
            }
            
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
                // Check if email already exists
                String checkQuery = "SELECT * FROM users WHERE email = ?";
                PreparedStatement checkStmt = conn.prepareStatement(checkQuery);
                checkStmt.setString(1, email);
                ResultSet rs = checkStmt.executeQuery();
                
                if (rs.next()) {
                    response.sendRedirect("index.jsp?error=emailexists");
                } else {
                    // Insert new user
                    String insertQuery = "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)";
                    PreparedStatement pstmt = conn.prepareStatement(insertQuery);
                    pstmt.setString(1, fullName);
                    pstmt.setString(2, email);
                    pstmt.setString(3, password);
                    
                    pstmt.executeUpdate();
                    response.sendRedirect("index.jsp?signup=success");
                }
            } catch (SQLException e) {
                e.printStackTrace();
                response.sendRedirect("index.jsp?error=database");
            }
        }
    }
}