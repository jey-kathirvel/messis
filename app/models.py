from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    mobile_number: Mapped[str | None] = mapped_column(String(20), unique=True)
    email: Mapped[str | None] = mapped_column(String(254), index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="Farm Owner")
    passcode_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="owner")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class PasscodeResetToken(Base):
    __tablename__ = "passcode_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )

class Farm(Base):
    __tablename__ = "farms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(140), nullable=False)
    location: Mapped[str | None] = mapped_column(String(255))
    acreage: Mapped[str | None] = mapped_column(String(40))
    total_trees: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
    )


    coconut_trees: Mapped[list["CoconutTree"]] = relationship(
        back_populates="farm",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class CoconutTree(Base):
    __tablename__ = "coconut_trees"
    __table_args__ = (
        UniqueConstraint(
            "farm_id",
            "tree_code",
            name="uq_coconut_trees_farm_tree_code",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    farm_id: Mapped[int] = mapped_column(
        ForeignKey("farms.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    tree_code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    tree_name: Mapped[str | None] = mapped_column(
        String(120),
    )

    qr_code_id: Mapped[str | None] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )

    variety: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Tall",
    )

    planting_date: Mapped[date | None] = mapped_column(Date)

    block_name: Mapped[str | None] = mapped_column(
        String(80),
    )

    row_number: Mapped[str | None] = mapped_column(
        String(40),
    )

    position_number: Mapped[str | None] = mapped_column(
        String(40),
    )

    health_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Healthy",
        index=True,
    )

    height_m: Mapped[Decimal | None] = mapped_column(
        Numeric(8, 2),
    )

    canopy_diameter_m: Mapped[Decimal | None] = mapped_column(
        Numeric(8, 2),
    )

    trunk_girth_cm: Mapped[Decimal | None] = mapped_column(
        Numeric(8, 2),
    )

    remarks: Mapped[str | None] = mapped_column(Text)

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    farm: Mapped["Farm"] = relationship(
        back_populates="coconut_trees",
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


# PATCH-005B.1: TREE ACTIVITY MODEL

from datetime import date as tree_activity_date
from datetime import datetime as tree_activity_datetime
from decimal import Decimal as TreeActivityDecimal

from sqlalchemy import (
    Date as TreeActivityDate,
    DateTime as TreeActivityDateTime,
    ForeignKey as TreeActivityForeignKey,
    Index as TreeActivityIndex,
    Integer as TreeActivityInteger,
    Numeric as TreeActivityNumeric,
    String as TreeActivityString,
    Text as TreeActivityText,
    UniqueConstraint as TreeActivityUniqueConstraint,
    func as tree_activity_func,
)
from sqlalchemy.orm import (
    Mapped as TreeActivityMapped,
    mapped_column as tree_activity_mapped_column,
)


class TreeActivity(Base):
    __tablename__ = "tree_activities"

    __table_args__ = (
        TreeActivityIndex(
            "ix_tree_activities_farm_tree_date",
            "farm_id",
            "tree_id",
            "activity_date",
        ),
        TreeActivityIndex(
            "ix_tree_activities_type_status",
            "activity_type",
            "status",
        ),
        TreeActivityIndex(
            "ix_tree_activities_next_due_date",
            "next_due_date",
        ),
    )

    id: TreeActivityMapped[int] = (
        tree_activity_mapped_column(
            TreeActivityInteger,
            primary_key=True,
            autoincrement=True,
        )
    )

    farm_id: TreeActivityMapped[int] = (
        tree_activity_mapped_column(
            TreeActivityForeignKey(
                "farms.id",
                ondelete="CASCADE",
            ),
            nullable=False,
            index=True,
        )
    )

    tree_id: TreeActivityMapped[int] = (
        tree_activity_mapped_column(
            TreeActivityForeignKey(
                "coconut_trees.id",
                ondelete="CASCADE",
            ),
            nullable=False,
            index=True,
        )
    )

    activity_type: TreeActivityMapped[str] = (
        tree_activity_mapped_column(
            TreeActivityString(50),
            nullable=False,
            index=True,
        )
    )

    activity_date: TreeActivityMapped[
        tree_activity_date
    ] = tree_activity_mapped_column(
        TreeActivityDate,
        nullable=False,
        index=True,
    )

    status: TreeActivityMapped[str] = (
        tree_activity_mapped_column(
            TreeActivityString(30),
            nullable=False,
            default="completed",
            server_default="completed",
            index=True,
        )
    )

    title: TreeActivityMapped[str] = (
        tree_activity_mapped_column(
            TreeActivityString(150),
            nullable=False,
        )
    )

    description: TreeActivityMapped[
        str | None
    ] = tree_activity_mapped_column(
        TreeActivityText,
        nullable=True,
    )

    quantity: TreeActivityMapped[
        TreeActivityDecimal | None
    ] = tree_activity_mapped_column(
        TreeActivityNumeric(
            12,
            3,
        ),
        nullable=True,
    )

    unit: TreeActivityMapped[
        str | None
    ] = tree_activity_mapped_column(
        TreeActivityString(30),
        nullable=True,
    )

    cost: TreeActivityMapped[
        TreeActivityDecimal | None
    ] = tree_activity_mapped_column(
        TreeActivityNumeric(
            12,
            2,
        ),
        nullable=True,
    )

    performed_by: TreeActivityMapped[
        str | None
    ] = tree_activity_mapped_column(
        TreeActivityString(120),
        nullable=True,
    )

    next_due_date: TreeActivityMapped[
        tree_activity_date | None
    ] = tree_activity_mapped_column(
        TreeActivityDate,
        nullable=True,
    )

    notes: TreeActivityMapped[
        str | None
    ] = tree_activity_mapped_column(
        TreeActivityText,
        nullable=True,
    )

    created_at: TreeActivityMapped[
        tree_activity_datetime
    ] = tree_activity_mapped_column(
        TreeActivityDateTime(
            timezone=True,
        ),
        nullable=False,
        server_default=tree_activity_func.now(),
    )

    updated_at: TreeActivityMapped[
        tree_activity_datetime
    ] = tree_activity_mapped_column(
        TreeActivityDateTime(
            timezone=True,
        ),
        nullable=False,
        server_default=tree_activity_func.now(),
        onupdate=tree_activity_func.now(),
    )

    def __repr__(self) -> str:
        return (
            "<TreeActivity "
            f"id={self.id!r} "
            f"tree_id={self.tree_id!r} "
            f"activity_type={self.activity_type!r} "
            f"activity_date={self.activity_date!r}>"
        )

# PATCH-HARVEST-001A: HARVEST CYCLE FOUNDATION


class HarvestCycle(Base):
    __tablename__ = "harvest_cycles"

    __table_args__ = (
        UniqueConstraint(
            "farm_id",
            "cycle_number",
            name="uq_harvest_cycles_farm_cycle",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    farm_id: Mapped[int] = mapped_column(
        ForeignKey(
            "farms.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    cycle_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    previous_harvest_date: Mapped[date | None] = (
        mapped_column(Date)
    )

    planned_harvest_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )

    minimum_due_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    maximum_due_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    actual_harvest_date: Mapped[date | None] = (
        mapped_column(Date)
    )

    harvest_interval_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=47,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Planned",
        index=True,
    )

    assigned_worker: Mapped[str | None] = mapped_column(
        String(150),
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class HarvestPhase(Base):
    """Editable operational stage within a harvest cycle."""
    __tablename__ = "harvest_phases"
    __table_args__ = (
        UniqueConstraint("harvest_cycle_id", "phase_order", name="uq_harvest_phase_order"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    harvest_cycle_id: Mapped[int] = mapped_column(
        ForeignKey("harvest_cycles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    phase_order: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    start_day: Mapped[int] = mapped_column(Integer, nullable=False)
    end_day: Mapped[int] = mapped_column(Integer, nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    due_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="UPCOMING", nullable=False, index=True)
    is_ai_recommended: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

# PATCH-HARVEST-002A: HARVEST RECORDING FOUNDATION


class HarvestRecord(Base):
    __tablename__ = "harvest_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    farm_id: Mapped[int] = mapped_column(
        ForeignKey(
            "farms.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    harvest_cycle_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "harvest_cycles.id",
            ondelete="SET NULL",
        ),
        index=True,
    )

    harvest_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )

    trees_harvested: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    mature_coconuts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    tender_coconuts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    damaged_coconuts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    total_coconuts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    estimated_weight_kg: Mapped[Decimal | None] = mapped_column(
        Numeric(12, 2),
    )

    labour_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    labour_cost: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    climbing_cost: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    transport_cost: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    other_cost: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    total_harvest_cost: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    buyer_or_destination: Mapped[str | None] = mapped_column(
        String(180),
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

# PATCH-EXPENSE-001A: EXPENSE DATABASE FOUNDATION


class ExpenseCategory(Base):
    __tablename__ = "expense_categories"

    __table_args__ = (
        UniqueConstraint(
            "owner_id",
            "name",
            name="uq_expense_categories_owner_name",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    icon: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="📂",
        server_default="📂",
    )

    color: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="#059669",
        server_default="#059669",
    )

    display_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
        server_default="100",
    )

    is_system: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )


class Vendor(Base):
    __tablename__ = "vendors"

    __table_args__ = (
        UniqueConstraint(
            "owner_id",
            "name",
            name="uq_vendors_owner_name",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )

    vendor_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="General",
        server_default="General",
    )

    mobile_number: Mapped[str | None] = mapped_column(
        String(20),
    )

    email: Mapped[str | None] = mapped_column(
        String(180),
    )

    address: Mapped[str | None] = mapped_column(
        Text,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class Expense(Base):
    __tablename__ = "expenses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    farm_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "farms.id",
            ondelete="SET NULL",
        ),
        index=True,
    )

    category_id: Mapped[int] = mapped_column(
        ForeignKey(
            "expense_categories.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    vendor_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "vendors.id",
            ondelete="SET NULL",
        ),
        index=True,
    )

    expense_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    payment_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Cash",
    )

    reference_number: Mapped[str | None] = mapped_column(
        String(120),
    )

    is_recurring: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

# PATCH-SALES-001A: SALES DATABASE FOUNDATION


class Buyer(Base):
    __tablename__ = "buyers"

    __table_args__ = (
        UniqueConstraint(
            "owner_id",
            "name",
            name="uq_buyers_owner_name",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )

    mobile_number: Mapped[str | None] = mapped_column(
        String(20),
    )

    email: Mapped[str | None] = mapped_column(
        String(180),
    )

    address: Mapped[str | None] = mapped_column(Text)

    notes: Mapped[str | None] = mapped_column(Text)

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class Sale(Base):
    __tablename__ = "sales"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    farm_id: Mapped[int] = mapped_column(
        ForeignKey("farms.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    harvest_record_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "harvest_records.id",
            ondelete="SET NULL",
        ),
        index=True,
    )

    buyer_id: Mapped[int | None] = mapped_column(
        ForeignKey("buyers.id", ondelete="SET NULL"),
        index=True,
    )

    sale_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )

    product_type: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
    )

    quantity: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    unit: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Number",
    )

    rate: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    gross_amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    transport_deduction: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    commission_deduction: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    other_deduction: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    net_amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    paid_amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    balance_amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
        default=Decimal("0"),
    )

    payment_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Unpaid",
        index=True,
    )

    payment_due_date: Mapped[date | None] = mapped_column(
        Date,
    )

    reference_number: Mapped[str | None] = mapped_column(
        String(120),
    )

    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class SalePayment(Base):
    __tablename__ = "sale_payments"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    sale_id: Mapped[int] = mapped_column(
        ForeignKey("sales.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    payment_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )

    amount: Mapped[Decimal] = mapped_column(
        Numeric(14, 2),
        nullable=False,
    )

    payment_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Cash",
    )

    reference_number: Mapped[str | None] = mapped_column(
        String(120),
    )

    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )


# AGRO-FRAMEWORK-001: additive, versioned universal farm configuration.
# Existing coconut tables deliberately remain unchanged for zero-data-loss
# migration and backward compatibility.
class FarmCategory(Base):
    __tablename__ = "farm_categories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    icon: Mapped[str | None] = mapped_column(String(30))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class FarmType(Base):
    __tablename__ = "farm_types"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category_id: Mapped[int] = mapped_column(ForeignKey("farm_categories.id"), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    icon: Mapped[str | None] = mapped_column(String(30))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class FarmTemplate(Base):
    __tablename__ = "farm_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_code: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    template_name: Mapped[str] = mapped_column(String(140), nullable=False)
    farm_type_id: Mapped[int] = mapped_column(ForeignKey("farm_types.id"), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_system_template: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class FarmTemplateVersion(Base):
    __tablename__ = "farm_template_versions"
    __table_args__ = (UniqueConstraint("template_id", "version", name="uq_template_version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("farm_templates.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="DRAFT", nullable=False, index=True)
    terminology_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    dashboard_widgets_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TemplateField(Base):
    __tablename__ = "template_fields"
    __table_args__ = (UniqueConstraint("template_version_id", "field_key", name="uq_template_field_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_version_id: Mapped[int] = mapped_column(ForeignKey("farm_template_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    section_name: Mapped[str] = mapped_column(String(100), default="Farm details", nullable=False)
    field_key: Mapped[str] = mapped_column(String(80), nullable=False)
    field_label: Mapped[str] = mapped_column(String(140), nullable=False)
    field_type: Mapped[str] = mapped_column(String(30), nullable=False)
    help_text: Mapped[str | None] = mapped_column(Text)
    is_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_value: Mapped[str | None] = mapped_column(Text)
    validation_rules_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    conditional_rules_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    options_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    unit_type: Mapped[str | None] = mapped_column(String(40))
    display_order: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class UserSetupProfile(Base):
    __tablename__ = "user_setup_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="NOT_STARTED", nullable=False)
    current_step: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    draft_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class FarmTemplateAssignment(Base):
    __tablename__ = "farm_template_assignments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    template_version_id: Mapped[int] = mapped_column(ForeignKey("farm_template_versions.id"), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class FarmFieldValue(Base):
    __tablename__ = "farm_field_values"
    __table_args__ = (UniqueConstraint("farm_id", "template_field_id", name="uq_farm_field_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    template_field_id: Mapped[int] = mapped_column(ForeignKey("template_fields.id", ondelete="CASCADE"), nullable=False)
    value_json: Mapped[object | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class FarmTask(Base):
    """A farm-scoped work item with a simple New -> Pending -> Closed lifecycle."""
    __tablename__ = "farm_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False, index=True)
    due_date: Mapped[date | None] = mapped_column(Date, index=True)
    status: Mapped[str] = mapped_column(String(20), default="NEW", nullable=False, index=True)
    worker_name: Mapped[str | None] = mapped_column(String(140))
    worker_phone: Mapped[str | None] = mapped_column(String(30))
    assignment_notes: Mapped[str | None] = mapped_column(Text)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


# PATCH-IRR-001: SMART IRRIGATION & FERTIGATION DATABASE FOUNDATION
# Additive tables only. Existing farm, harvest, finance, and tree data remain
# untouched. All operational records are owner-scoped for tenant isolation.
class IrrigationZone(Base):
    __tablename__ = "irrigation_zones"
    __table_args__ = (
        UniqueConstraint("farm_id", "name", name="uq_irrigation_zone_farm_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(140), nullable=False)
    crop_name: Mapped[str | None] = mapped_column(String(120))
    crop_variety: Mapped[str | None] = mapped_column(String(120))
    growth_stage: Mapped[str | None] = mapped_column(String(80))
    plant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    area_value: Mapped[Decimal | None] = mapped_column(Numeric(12, 3))
    area_unit: Mapped[str] = mapped_column(String(20), nullable=False, default="acre")
    soil_type: Mapped[str | None] = mapped_column(String(80))
    irrigation_method: Mapped[str] = mapped_column(String(40), nullable=False, default="drip", index=True)
    recommended_litres_per_plant: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    recommended_interval_days: Mapped[int | None] = mapped_column(Integer)
    last_irrigation_date: Mapped[date | None] = mapped_column(Date)
    next_irrigation_date: Mapped[date | None] = mapped_column(Date, index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class WaterSource(Base):
    __tablename__ = "water_sources"
    __table_args__ = (
        UniqueConstraint("farm_id", "name", name="uq_water_source_farm_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(140), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    capacity_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    current_level_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    flow_rate_lpm: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    water_quality_status: Mapped[str | None] = mapped_column(String(40))
    last_quality_test_date: Mapped[date | None] = mapped_column(Date)
    availability_status: Mapped[str] = mapped_column(String(30), nullable=False, default="available", index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IrrigationPump(Base):
    __tablename__ = "irrigation_pumps"
    __table_args__ = (
        UniqueConstraint("farm_id", "name", name="uq_irrigation_pump_farm_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    water_source_id: Mapped[int | None] = mapped_column(ForeignKey("water_sources.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(140), nullable=False)
    pump_type: Mapped[str | None] = mapped_column(String(60))
    horsepower: Mapped[Decimal | None] = mapped_column(Numeric(8, 2))
    flow_rate_lpm: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    power_source: Mapped[str | None] = mapped_column(String(30))
    operating_cost_per_hour: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    installation_date: Mapped[date | None] = mapped_column(Date)
    last_service_date: Mapped[date | None] = mapped_column(Date)
    next_service_date: Mapped[date | None] = mapped_column(Date, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="available", index=True)
    fault_details: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IrrigationPlan(Base):
    __tablename__ = "irrigation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(40), nullable=False, default="custom_interval")
    interval_days: Mapped[int | None] = mapped_column(Integer)
    planned_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    litres_per_plant: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    estimated_duration_minutes: Mapped[int | None] = mapped_column(Integer)
    weather_adjustment_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    fertigation_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active", index=True)
    instructions: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IrrigationSchedule(Base):
    __tablename__ = "irrigation_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_plans.id", ondelete="SET NULL"), index=True)
    water_source_id: Mapped[int | None] = mapped_column(ForeignKey("water_sources.id", ondelete="SET NULL"), index=True)
    pump_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="SET NULL"), index=True)
    scheduled_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    scheduled_start_time: Mapped[str | None] = mapped_column(String(10))
    planned_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    estimated_duration_minutes: Mapped[int | None] = mapped_column(Integer)
    assigned_worker: Mapped[str | None] = mapped_column(String(140))
    recurrence_type: Mapped[str] = mapped_column(String(20), nullable=False, default="none")
    recurrence_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recurrence_end_date: Mapped[date | None] = mapped_column(Date, index=True)
    recurrence_group_id: Mapped[str | None] = mapped_column(String(64), index=True)
    fertigation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    weather_recommendation: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="planned", index=True)
    instructions: Mapped[str | None] = mapped_column(Text)
    postponed_from_date: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IrrigationExecution(Base):
    __tablename__ = "irrigation_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    schedule_id: Mapped[int] = mapped_column(ForeignKey("irrigation_schedules.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="in_progress", index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_paused_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    actual_duration_minutes: Mapped[int | None] = mapped_column(Integer)
    actual_water_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    opening_meter_reading: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    closing_meter_reading: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    opening_tank_level_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    closing_tank_level_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    completion_percentage: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    leakage_reported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pump_issue_reported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    worker_remarks: Mapped[str | None] = mapped_column(Text)
    supervisor_approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    supervisor_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    supervisor_notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class FertilizerProduct(Base):
    __tablename__ = "fertilizer_products"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_fertilizer_product_owner_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    manufacturer: Mapped[str | None] = mapped_column(String(140))
    unit: Mapped[str] = mapped_column(String(20), nullable=False, default="kg")
    stock_quantity: Mapped[Decimal] = mapped_column(Numeric(14, 3), nullable=False, default=Decimal("0"))
    safe_concentration_per_1000l: Mapped[Decimal | None] = mapped_column(Numeric(12, 3))
    expiry_date: Mapped[date | None] = mapped_column(Date, index=True)
    compatibility_notes: Mapped[str | None] = mapped_column(Text)
    safety_instructions: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class FertigationPlan(Base):
    __tablename__ = "fertigation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_schedules.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    planned_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    growth_stage: Mapped[str | None] = mapped_column(String(80))
    total_water_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    tank_capacity_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    number_of_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    initial_flush_minutes: Mapped[int | None] = mapped_column(Integer)
    injection_minutes: Mapped[int | None] = mapped_column(Integer)
    final_flush_minutes: Mapped[int | None] = mapped_column(Integer)
    agronomist_reference: Mapped[str | None] = mapped_column(String(255))
    assigned_worker: Mapped[str | None] = mapped_column(String(140))
    approval_status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="planned", index=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_notes: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_remarks: Mapped[str | None] = mapped_column(Text)
    stock_deducted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    safety_instructions: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class FertigationPlanItem(Base):
    __tablename__ = "fertigation_plan_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    fertigation_plan_id: Mapped[int] = mapped_column(ForeignKey("fertigation_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    fertilizer_product_id: Mapped[int] = mapped_column(ForeignKey("fertilizer_products.id", ondelete="RESTRICT"), nullable=False, index=True)
    quantity: Mapped[Decimal] = mapped_column(Numeric(14, 3), nullable=False)
    unit: Mapped[str] = mapped_column(String(20), nullable=False, default="kg")
    mixing_order: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    quantity_per_batch: Mapped[Decimal | None] = mapped_column(Numeric(14, 3))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class FertilizerStockMovement(Base):
    __tablename__ = "fertilizer_stock_movements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int | None] = mapped_column(ForeignKey("farms.id", ondelete="SET NULL"), index=True)
    fertilizer_product_id: Mapped[int] = mapped_column(ForeignKey("fertilizer_products.id", ondelete="RESTRICT"), nullable=False, index=True)
    fertigation_plan_id: Mapped[int | None] = mapped_column(ForeignKey("fertigation_plans.id", ondelete="SET NULL"), index=True)
    movement_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    quantity_change: Mapped[Decimal] = mapped_column(Numeric(14, 3), nullable=False)
    balance_after: Mapped[Decimal] = mapped_column(Numeric(14, 3), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)


class WeatherIrrigationRecommendation(Base):
    __tablename__ = "weather_irrigation_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_schedules.id", ondelete="CASCADE"), index=True)
    forecast_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    temperature_c: Mapped[Decimal | None] = mapped_column(Numeric(6, 2))
    humidity_percent: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    rain_probability_percent: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    forecast_rain_mm: Mapped[Decimal | None] = mapped_column(Numeric(8, 2))
    wind_speed_kph: Mapped[Decimal | None] = mapped_column(Numeric(8, 2))
    recommendation: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    adjustment_percent: Mapped[Decimal | None] = mapped_column(Numeric(6, 2))
    recommended_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    reason: Mapped[str | None] = mapped_column(Text)
    user_decision: Mapped[str] = mapped_column(String(30), nullable=False, default="pending", index=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_name: Mapped[str | None] = mapped_column(String(100))
    raw_weather_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class SoilMoistureReading(Base):
    __tablename__ = "soil_moisture_readings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    reading_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    moisture_percent: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    depth_cm: Mapped[Decimal | None] = mapped_column(Numeric(8, 2))
    source_type: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    sensor_reference: Mapped[str | None] = mapped_column(String(120))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class WaterMeterReading(Base):
    __tablename__ = "water_meter_readings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    water_source_id: Mapped[int | None] = mapped_column(ForeignKey("water_sources.id", ondelete="SET NULL"), index=True)
    pump_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="SET NULL"), index=True)
    execution_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_executions.id", ondelete="SET NULL"), index=True)
    reading_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    meter_value_litres: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    reading_type: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class IrrigationAlert(Base):
    __tablename__ = "irrigation_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), index=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_schedules.id", ondelete="CASCADE"), index=True)
    alert_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info", index=True)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open", index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IrrigationAttachment(Base):
    __tablename__ = "irrigation_attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_schedules.id", ondelete="CASCADE"), index=True)
    execution_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_executions.id", ondelete="CASCADE"), index=True)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(120))
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)
    attachment_type: Mapped[str] = mapped_column(String(30), nullable=False, default="other")
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


# PATCH-IRR-003: PUMPS AND IRRIGATION EQUIPMENT MANAGEMENT
class IrrigationEquipment(Base):
    __tablename__ = "irrigation_equipment"
    __table_args__ = (UniqueConstraint("farm_id", "name", name="uq_irrigation_equipment_farm_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="SET NULL"), index=True)
    pump_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(140), nullable=False)
    equipment_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    manufacturer: Mapped[str | None] = mapped_column(String(140))
    model_number: Mapped[str | None] = mapped_column(String(100))
    serial_number: Mapped[str | None] = mapped_column(String(120))
    installation_date: Mapped[date | None] = mapped_column(Date)
    purchase_cost: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="available", index=True)
    last_service_date: Mapped[date | None] = mapped_column(Date)
    next_service_date: Mapped[date | None] = mapped_column(Date, index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class PumpMaintenanceRecord(Base):
    __tablename__ = "pump_maintenance_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    pump_id: Mapped[int] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="CASCADE"), nullable=False, index=True)
    service_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    service_type: Mapped[str] = mapped_column(String(50), nullable=False)
    technician: Mapped[str | None] = mapped_column(String(140))
    cost: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    next_service_date: Mapped[date | None] = mapped_column(Date, index=True)
    work_performed: Mapped[str | None] = mapped_column(Text)
    parts_replaced: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class PumpRuntimeLog(Base):
    __tablename__ = "pump_runtime_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    pump_id: Mapped[int] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="CASCADE"), nullable=False, index=True)
    run_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    runtime_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    energy_kwh: Mapped[Decimal | None] = mapped_column(Numeric(12, 3))
    fuel_litres: Mapped[Decimal | None] = mapped_column(Numeric(12, 3))
    water_pumped_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    operating_cost: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


# PATCH-IRR-004: SMART WATER REQUIREMENT CALCULATOR
class WaterRequirementCalculation(Base):
    __tablename__ = "water_requirement_calculations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    farm_id: Mapped[int] = mapped_column(ForeignKey("farms.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("irrigation_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    pump_id: Mapped[int | None] = mapped_column(ForeignKey("irrigation_pumps.id", ondelete="SET NULL"), index=True)
    calculation_date: Mapped[date] = mapped_column(Date, nullable=False, default=date.today, index=True)
    plant_count: Mapped[int] = mapped_column(Integer, nullable=False)
    base_litres_per_plant: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    base_water_litres: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    soil_factor: Mapped[Decimal] = mapped_column(Numeric(8, 4), nullable=False, default=Decimal("1"))
    irrigation_efficiency: Mapped[Decimal] = mapped_column(Numeric(8, 4), nullable=False, default=Decimal("0.90"))
    temperature_c: Mapped[Decimal | None] = mapped_column(Numeric(6, 2))
    humidity_percent: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    rain_probability_percent: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    expected_rain_mm: Mapped[Decimal | None] = mapped_column(Numeric(8, 2))
    weather_adjustment_percent: Mapped[Decimal] = mapped_column(Numeric(8, 2), nullable=False, default=Decimal("0"))
    effective_rain_litres: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False, default=Decimal("0"))
    final_water_litres: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    water_saved_litres: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False, default=Decimal("0"))
    estimated_runtime_minutes: Mapped[int | None] = mapped_column(Integer)
    estimated_operating_cost: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    recommendation: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    recommendation_reason: Mapped[str | None] = mapped_column(Text)
    user_override_litres: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
