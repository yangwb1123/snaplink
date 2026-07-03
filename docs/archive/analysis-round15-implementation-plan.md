# CSRF Protection Enhancement

## Summary
Add Origin header validation as defense-in-depth for `/auth/login` endpoint.

## Problem
Current CSRF protection relies solely on Content-Type validation (rejecting non-JSON). 
While effective, adding Origin validation provides defense-in-depth against cross-origin attacks.

## Solution
1. Add Origin header validation middleware
2. Reject requests where Origin doesn't match allowed origins
3. Log security events for blocked origins

## Implementation
