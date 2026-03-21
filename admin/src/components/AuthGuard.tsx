import { Navigate, Outlet } from "react-router";
import { useAuth } from "../App";
import Layout from "./Layout";

export default function AuthGuard() {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return <Layout><Outlet /></Layout>;
}
