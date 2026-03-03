"""Repository for SavedSearch operations."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session, joinedload

from ion.models.saved_search import SavedSearch, SearchType


class SavedSearchRepository:
    """Repository for SavedSearch CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        search_params: dict,
        created_by_id: int,
        description: str | None = None,
        search_type: str = SearchType.DISCOVER.value,
        is_shared: bool = False,
    ) -> SavedSearch:
        """Create a new saved search."""
        saved_search = SavedSearch(
            name=name,
            description=description,
            search_type=search_type,
            search_params=search_params,
            created_by_id=created_by_id,
            is_shared=is_shared,
            is_favorite=False,
            execution_count=0,
        )
        self.session.add(saved_search)
        self.session.flush()
        return saved_search

    def get_by_id(self, search_id: int) -> Optional[SavedSearch]:
        """Get a saved search by ID."""
        stmt = (
            select(SavedSearch)
            .options(joinedload(SavedSearch.created_by))
            .where(SavedSearch.id == search_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_for_user(
        self,
        user_id: int,
        search_type: str | None = None,
        favorites_only: bool = False,
    ) -> List[SavedSearch]:
        """
        List saved searches for a user.
        Returns user's own searches plus shared searches from others.
        """
        stmt = select(SavedSearch).options(joinedload(SavedSearch.created_by))

        # User's own searches OR shared searches
        stmt = stmt.where(
            or_(
                SavedSearch.created_by_id == user_id,
                SavedSearch.is_shared == True,
            )
        )

        if search_type:
            stmt = stmt.where(SavedSearch.search_type == search_type)

        if favorites_only:
            # Only show favorites for user's own searches
            stmt = stmt.where(
                SavedSearch.created_by_id == user_id,
                SavedSearch.is_favorite == True,
            )

        # Order by: favorites first, then by name
        stmt = stmt.order_by(
            SavedSearch.is_favorite.desc(),
            SavedSearch.name,
        )

        return list(self.session.execute(stmt).unique().scalars().all())

    def list_user_owned(self, user_id: int) -> List[SavedSearch]:
        """List only searches owned by a specific user."""
        stmt = (
            select(SavedSearch)
            .options(joinedload(SavedSearch.created_by))
            .where(SavedSearch.created_by_id == user_id)
            .order_by(SavedSearch.is_favorite.desc(), SavedSearch.name)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def list_shared(self, exclude_user_id: int | None = None) -> List[SavedSearch]:
        """List all shared searches, optionally excluding a user's own."""
        stmt = (
            select(SavedSearch)
            .options(joinedload(SavedSearch.created_by))
            .where(SavedSearch.is_shared == True)
        )

        if exclude_user_id:
            stmt = stmt.where(SavedSearch.created_by_id != exclude_user_id)

        stmt = stmt.order_by(SavedSearch.name)
        return list(self.session.execute(stmt).unique().scalars().all())

    def update(
        self,
        saved_search: SavedSearch,
        name: str | None = None,
        description: str | None = None,
        search_params: dict | None = None,
        is_shared: bool | None = None,
    ) -> SavedSearch:
        """Update a saved search."""
        if name is not None:
            saved_search.name = name
        if description is not None:
            saved_search.description = description
        if search_params is not None:
            saved_search.search_params = search_params
        if is_shared is not None:
            saved_search.is_shared = is_shared
        self.session.flush()
        return saved_search

    def delete(self, saved_search: SavedSearch) -> None:
        """Delete a saved search."""
        self.session.delete(saved_search)
        self.session.flush()

    def record_execution(self, saved_search: SavedSearch) -> SavedSearch:
        """Record that a saved search was executed."""
        saved_search.execution_count += 1
        saved_search.last_executed_at = datetime.utcnow()
        self.session.flush()
        return saved_search

    def toggle_favorite(self, saved_search: SavedSearch) -> SavedSearch:
        """Toggle the favorite status of a saved search."""
        saved_search.is_favorite = not saved_search.is_favorite
        self.session.flush()
        return saved_search

    def search(self, query: str, user_id: int) -> List[SavedSearch]:
        """Search saved searches by name or description."""
        pattern = f"%{query}%"
        stmt = (
            select(SavedSearch)
            .options(joinedload(SavedSearch.created_by))
            .where(
                or_(
                    SavedSearch.created_by_id == user_id,
                    SavedSearch.is_shared == True,
                )
            )
            .where(
                or_(
                    SavedSearch.name.ilike(pattern),
                    SavedSearch.description.ilike(pattern),
                )
            )
            .order_by(SavedSearch.name)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def get_popular(self, limit: int = 10) -> List[SavedSearch]:
        """Get most executed shared searches."""
        stmt = (
            select(SavedSearch)
            .options(joinedload(SavedSearch.created_by))
            .where(SavedSearch.is_shared == True)
            .order_by(SavedSearch.execution_count.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).unique().scalars().all())
