<html>
<head>
<title>Sessions</title>
</head>

<body>
<table>
<%
    for (de.garnix.sshoauthmux.SshClientConnectInfo s : de.garnix.sshoauthmux.SshClientConnectInfo.getSessions()) {
%>
<tr>
  <td><%= Integer.toHexString(s.getClientKeyHC()).toUpperCase() %></td>
  <td><%= s.session.getRemoteAddress() %></td>
  <td><%= ! s.session.isClosing() %></td>
  <td><%= s.session.hashCode() %></td>
  <td><%= s.forwarder() %></td>
</tr>
<%   }  %>
</table>
</body>

</html>