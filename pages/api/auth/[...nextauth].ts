import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
// import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import prisma from "@/lib/prismadb";
import jwt from "jsonwebtoken";
import { JWT } from "next-auth/jwt";
import { compare } from "bcryptjs";

export default NextAuth({
  pages: {
    signIn: "/auth/signin",
  },
  session: {
    strategy: "jwt",
  },
  jwt: {
    encode({ token }) {
      if (!process.env.NEXTAUTH_SECRET) {
        throw new Error("NEXTAUTH_SECRET is not set");
      }
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return jwt.sign(token!, process.env.NEXTAUTH_SECRET);
    },
    decode({ token }) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return jwt.verify(token!, process.env.NEXTAUTH_SECRET!) as JWT;
    },
  },
  // Include user.id on session
  callbacks: {
    session({ session, token }) {
      if (session.user) {
        session.user.id = token.sub ?? "";
      }
      return session;
    },
  },
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "Credentials",
      type: "credentials",
      id: "credentials",
      credentials: {
        email: {
          label: "Email",
          type: "text",
          placeholder: "jsmith@gmail.com",
        },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        if (!credentials) {
          return null;
        }
        const user = await prisma.user.findUnique({
          where: {
            email: credentials.email,
          },
        });
        if (!user || !user.password) {
          throw new Error("Invalid email/password");
        }
        const isValid = await compare(credentials.password, user.password);
        if (!isValid) {
          throw new Error("Invalid email/password");
        }
        return user;
      },
    }),
    //     GoogleProvider({
    //       clientId: process.env.GOOGLE_CLIENT_ID,
    //       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    //     }),
  ],
});
