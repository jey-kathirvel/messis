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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    mobile_number: Mapped[str | None] = mapped_column(String(20), unique=True)
    display_name: Mapped[str] = mapped_column(String(120), default="Farm Owner")
    passcode_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="owner")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

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
