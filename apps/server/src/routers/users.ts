import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, publicProcedure, router } from "../lib/trpc";
import prisma from "../../prisma";
import bcrypt from "bcryptjs";

// Input schemas
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1),
  universityId: z.string(),
  major: z.string().optional(),
  graduationYear: z.number().int().min(1900).max(2100).optional(),
  dormLocation: z.string().optional(),
  phoneNumber: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const updateProfileSchema = z.object({
  name: z.string().min(1).optional(),
  major: z.string().optional(),
  graduationYear: z.number().int().min(1900).max(2100).optional(),
  dormLocation: z.string().optional(),
  phoneNumber: z.string().optional(),
  profileImage: z.string().url().optional(),
});

const userIdSchema = z.object({
  userId: z.string(),
});

export const usersRouter = router({
  // POST /api/users/register
  register: publicProcedure
    .input(registerSchema)
    .mutation(async ({ input }) => {
      try {
        // Check if user already exists
        const existingUser = await (prisma as any).user.findUnique({
          where: { email: input.email },
        });

        if (existingUser) {
          throw new TRPCError({
            code: "CONFLICT",
            message: "User with this email already exists",
          });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(input.password, 12);

        // Create user with basic fields
        const user = await (prisma as any).user.create({
          data: {
            email: input.email,
            name: input.name,
            major: input.major,
            graduationYear: input.graduationYear,
            dormLocation: input.dormLocation,
            phoneNumber: input.phoneNumber,
          },
        });

        // Create account with hashed password
        await (prisma as any).account.create({
          data: {
            accountId: user.id,
            providerId: "credentials",
            userId: user.id,
            password: hashedPassword,
          },
        });

        return {
          success: true,
          message: "User registered successfully",
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
          },
        };
      } catch (error) {
        if (error instanceof TRPCError) {
          throw error;
        }
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to register user",
        });
      }
    }),

  // POST /api/users/login
  login: publicProcedure.input(loginSchema).mutation(async ({ input }) => {
    try {
      // Find user by email
      const user = await (prisma as any).user.findUnique({
        where: { email: input.email },
        include: {
          accounts: {
            where: { providerId: "credentials" },
          },
        },
      });

      if (!user || !user.accounts[0]) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid email or password",
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(
        input.password,
        user.accounts[0].password || ""
      );

      if (!isValidPassword) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid email or password",
        });
      }

      return {
        success: true,
        message: "Login successful",
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    } catch (error) {
      if (error instanceof TRPCError) {
        throw error;
      }
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to authenticate user",
      });
    }
  }),

  // GET /api/users/me
  me: protectedProcedure.query(async ({ ctx }) => {
    try {
      const user = await (prisma as any).user.findUnique({
        where: { id: ctx.session.user.id },
      });

      if (!user) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "User not found",
        });
      }

      return {
        id: user.id,
        email: user.email,
        name: user.name,
        major: user.major,
        graduationYear: user.graduationYear,
        dormLocation: user.dormLocation,
        phoneNumber: user.phoneNumber,
        profileImage: user.profileImage,
        reputationScore: user.reputationScore,
        totalTrades: user.totalTrades,
        createdAt: user.createdAt,
        lastActive: user.lastActive,
      };
    } catch (error) {
      if (error instanceof TRPCError) {
        throw error;
      }
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch user profile",
      });
    }
  }),

  // PUT /api/users/me
  updateMe: protectedProcedure
    .input(updateProfileSchema)
    .mutation(async ({ ctx, input }) => {
      try {
        const updatedUser = await (prisma as any).user.update({
          where: { id: ctx.session.user.id },
          data: { ...input, updatedAt: new Date() },
        });

        return {
          success: true,
          message: "Profile updated successfully",
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            name: updatedUser.name,
            major: updatedUser.major,
            graduationYear: updatedUser.graduationYear,
            dormLocation: updatedUser.dormLocation,
            phoneNumber: updatedUser.phoneNumber,
            profileImage: updatedUser.profileImage,
          },
        };
      } catch (error) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to update user profile",
        });
      }
    }),

  // GET /api/users/:userId
  getById: publicProcedure.input(userIdSchema).query(async ({ input }) => {
    try {
      const user = await (prisma as any).user.findUnique({
        where: { id: input.userId },
        select: {
          id: true,
          name: true,
          major: true,
          graduationYear: true,
          profileImage: true,
          reputationScore: true,
          totalTrades: true,
          createdAt: true,
        },
      });

      if (!user) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "User not found",
        });
      }

      return {
        success: true,
        user,
      };
    } catch (error) {
      if (error instanceof TRPCError) {
        throw error;
      }
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch user profile",
      });
    }
  }),

  // GET /api/users/me/items
  myItems: protectedProcedure.query(async ({ ctx }) => {
    try {
      const items = await (prisma as any).item.findMany({
        where: { ownerId: ctx.session.user.id },
        orderBy: { createdAt: "desc" },
      });

      return {
        success: true,
        items,
      };
    } catch (error) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch user items",
      });
    }
  }),

  // GET /api/users/me/trades
  myTrades: protectedProcedure.query(async ({ ctx }) => {
    try {
      const trades = await (prisma as any).trade.findMany({
        where: {
          OR: [
            { senderId: ctx.session.user.id },
            { receiverId: ctx.session.user.id },
          ],
        },
        orderBy: { createdAt: "desc" },
      });

      return {
        success: true,
        trades,
      };
    } catch (error) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch user trades",
      });
    }
  }),

  // GET /api/users/me/reviews
  myReviews: protectedProcedure.query(async ({ ctx }) => {
    try {
      const reviews = await (prisma as any).review.findMany({
        where: {
          OR: [
            { reviewerId: ctx.session.user.id },
            { revieweeId: ctx.session.user.id },
          ],
        },
        orderBy: { createdAt: "desc" },
      });

      return {
        success: true,
        reviews,
      };
    } catch (error) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch user reviews",
      });
    }
  }),
});
