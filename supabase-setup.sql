-- ═══════════════════════════════════════════════════════════════════
--  INDU PURVANCHAL NIDHI LIMITED — COMPLETE SUPABASE SETUP
--  Naye project ke SQL Editor me POORA paste karke ek baar Run karo.
--  Isme schema + secure RLS policies (saare fixes ke saath) hain.
-- ═══════════════════════════════════════════════════════════════════

-- ════════════ 1. TABLES ════════════

CREATE TABLE IF NOT EXISTS profiles (
  id uuid REFERENCES auth.users PRIMARY KEY,
  name text,
  email text,
  role text DEFAULT 'employee',
  is_approved boolean DEFAULT false,
  approved_by uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clients (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  name text NOT NULL,
  father_name text, mother_name text, husband_wife_name text,
  marital_status text DEFAULT 'unmarried',
  dob date, age integer,
  client_type text DEFAULT 'individual',
  status text DEFAULT 'active',
  email text, phone text, phone2 text,
  address text, address2 text, city text, state text,
  pin_code text, country text DEFAULT 'India',
  aadhaar_no text, pan_no text,
  aadhaar_photo text, pan_photo text,
  kyc_approved boolean DEFAULT false,
  kyc_approved_by uuid REFERENCES profiles(id),
  balance numeric DEFAULT 0,
  interest_amount numeric DEFAULT 0,
  loan_amount numeric DEFAULT 0,
  emi_amount numeric DEFAULT 0,
  loan_weeks integer DEFAULT 12,
  loan_cycle text DEFAULT '1st',
  loan_purpose text,
  loan_date date, first_emi_date date,
  membership_date date, card_issue_date date,
  member_no text, guarantor_name text,
  finance_company text,
  bank_name text, account_no text,
  center_name text, center_code text, center_leader text,
  meeting_day text,
  gps_lat numeric, gps_lng numeric, gps_captured_at timestamptz,
  notes text, photo_url text,
  assigned_to uuid REFERENCES profiles(id),
  owner_id uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payments (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  client_id uuid REFERENCES clients(id) ON DELETE CASCADE,
  amount numeric NOT NULL,
  type text DEFAULT 'credit',
  description text,
  date date DEFAULT current_date,
  created_by uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invoices (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  client_id uuid REFERENCES clients(id) ON DELETE CASCADE,
  description text,
  amount numeric NOT NULL,
  status text DEFAULT 'pending',
  due_date date,
  created_by uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cash_book (
  entry_date date PRIMARY KEY,
  day_name text,
  opening numeric DEFAULT 0, collection numeric DEFAULT 0,
  lpf numeric DEFAULT 0, lpc numeric DEFAULT 0,
  prepayment numeric DEFAULT 0, overdue numeric DEFAULT 0,
  disbursement numeric DEFAULT 0, bank_deposit numeric DEFAULT 0,
  expense1 numeric DEFAULT 0, expense2 numeric DEFAULT 0, expense3 numeric DEFAULT 0,
  denom_2000 integer DEFAULT 0, denom_500 integer DEFAULT 0,
  denom_200 integer DEFAULT 0, denom_100 integer DEFAULT 0,
  denom_50 integer DEFAULT 0, denom_20 integer DEFAULT 0,
  denom_10 integer DEFAULT 0, denom_coin numeric DEFAULT 0,
  created_by uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collection_register (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  entry_date date NOT NULL,
  center_name text NOT NULL,
  due_collection numeric DEFAULT 0,
  pre_collection numeric DEFAULT 0,
  od_collection numeric DEFAULT 0,
  lpf numeric DEFAULT 0, lpc numeric DEFAULT 0,
  total_collection numeric DEFAULT 0,
  remark text,
  created_by uuid REFERENCES profiles(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS loan_history (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  client_id uuid REFERENCES clients(id) ON DELETE CASCADE,
  loan_cycle text,
  balance numeric DEFAULT 0,
  interest_amount numeric DEFAULT 0,
  loan_weeks integer DEFAULT 12,
  loan_date date, first_emi_date date,
  closed_date date, closed_at timestamptz,
  payment_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
);


-- ════════════ 2. RLS ENABLE ════════════

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE cash_book ENABLE ROW LEVEL SECURITY;
ALTER TABLE collection_register ENABLE ROW LEVEL SECURITY;
ALTER TABLE loan_history ENABLE ROW LEVEL SECURITY;


-- ════════════ 3. HELPER FUNCTIONS (recursion-free) ════════════

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin');
$$;

CREATE OR REPLACE FUNCTION public.is_approved_user()
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND is_approved = true);
$$;

CREATE OR REPLACE FUNCTION public.my_role()
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = public AS $$
  SELECT role FROM profiles WHERE id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION public.my_approved()
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = public AS $$
  SELECT is_approved FROM profiles WHERE id = auth.uid();
$$;


-- ════════════ 4. POLICIES ════════════

-- PROFILES
CREATE POLICY profiles_read ON profiles FOR SELECT
USING (auth.uid() = id OR public.is_admin());

CREATE POLICY profiles_insert_own ON profiles FOR INSERT
WITH CHECK (auth.uid() = id AND role = 'employee' AND is_approved = false);

CREATE POLICY profiles_update_self ON profiles FOR UPDATE
USING (auth.uid() = id)
WITH CHECK (auth.uid() = id AND role = public.my_role() AND is_approved = public.my_approved());

CREATE POLICY profiles_admin_update ON profiles FOR UPDATE
USING (public.is_admin());

-- CLIENTS
CREATE POLICY clients_select ON clients FOR SELECT
USING (public.is_admin() OR (assigned_to = auth.uid() AND public.is_approved_user()));

CREATE POLICY clients_insert ON clients FOR INSERT
WITH CHECK (public.is_approved_user());

CREATE POLICY clients_update ON clients FOR UPDATE
USING (public.is_admin() OR (assigned_to = auth.uid() AND public.is_approved_user()));

CREATE POLICY clients_delete ON clients FOR DELETE
USING (public.is_admin());

-- PAYMENTS
CREATE POLICY payments_select ON payments FOR SELECT
USING (
  public.is_admin()
  OR ( public.is_approved_user() AND EXISTS (
        SELECT 1 FROM clients c
        WHERE c.id = payments.client_id AND c.assigned_to = auth.uid() ) )
);

CREATE POLICY payments_insert ON payments FOR INSERT
WITH CHECK (public.is_approved_user());

CREATE POLICY payments_delete ON payments FOR DELETE
USING (public.is_admin() OR (created_by = auth.uid() AND public.is_approved_user()));

-- INVOICES
CREATE POLICY invoices_select ON invoices FOR SELECT
USING (
  public.is_admin()
  OR ( public.is_approved_user() AND EXISTS (
        SELECT 1 FROM clients c
        WHERE c.id = invoices.client_id AND c.assigned_to = auth.uid() ) )
);

CREATE POLICY invoices_insert ON invoices FOR INSERT
WITH CHECK (public.is_approved_user());

CREATE POLICY invoices_update ON invoices FOR UPDATE
USING (public.is_admin() OR (created_by = auth.uid() AND public.is_approved_user()));

-- CASH BOOK / COLLECTION REGISTER / LOAN HISTORY (approved staff)
CREATE POLICY cash_book_all ON cash_book FOR ALL
USING (public.is_approved_user()) WITH CHECK (public.is_approved_user());

CREATE POLICY collreg_all ON collection_register FOR ALL
USING (public.is_approved_user()) WITH CHECK (public.is_approved_user());

CREATE POLICY loan_history_all ON loan_history FOR ALL
USING (public.is_approved_user()) WITH CHECK (public.is_approved_user());


-- ════════════ 5. STORAGE (PRIVATE bucket — KYC docs safe) ════════════

INSERT INTO storage.buckets (id, name, public)
VALUES ('client-photos', 'client-photos', false)
ON CONFLICT (id) DO UPDATE SET public = false;

CREATE POLICY photos_read ON storage.objects FOR SELECT
USING (bucket_id = 'client-photos' AND public.is_approved_user());

CREATE POLICY photos_upload ON storage.objects FOR INSERT
WITH CHECK (bucket_id = 'client-photos' AND public.is_approved_user());

CREATE POLICY photos_delete ON storage.objects FOR DELETE
USING (bucket_id = 'client-photos' AND public.is_admin());


-- ════════════ 6. CLIENT KO ADMIN BANANA (signup ke BAAD) ════════════
-- Client app me signup kar le, phir uska email daal ke yeh run karo:

-- UPDATE profiles SET role = 'admin', is_approved = true
-- WHERE email = 'CLIENT_KA_EMAIL_YAHAN';

-- ✅ DONE! Database ready hai.
